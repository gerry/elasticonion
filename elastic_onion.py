# Elastic Onion: Getting onionscan results into elastic search.
import os
import re
import sys
import time
import json
import random
import logging
import threading
import subprocess
import beanstalkc
import redis
import stem
from stem import control


TOR_CONTROL_PASSWORD = "mysecrettorpassword"
BEANSTALK_SERVER = dict(host='localhost', port=11300)
REDIS_SERVER = dict(host="localhost", port=6379, db=0)
ONION_QUEUE = "onions"
NO_JOB_SLEEP = 300
ONION_SCAN_TIMEOUT = 300
IDENTITY_LOCK_TIMEOUT = None
BEANSTALK_TTR = 330
PATH_TO_ONIONSCAN = "./gocode/bin/onionscan"
# This needs work...
VALID_ONION_RE = '\.onion\/?(\:\d{1,5})?/?$'
NUM_WORKERS = 4


# Populate a BS queue with some known onion sites.
def load_onion_list():
    beanstalk = beanstalkc.Connection(**BEANSTALK_SERVER)
    beanstalk.use(ONION_QUEUE)

    if os.path.exists("onion_master_list.txt"):
        with open("onion_master_list.txt", "rb") as fd:
            stored_onions = fd.read().splitlines()
    else:
        logging.debug('No onion master list. Download it!')
        sys.exit(0)

    random.shuffle(stored_onions)

    count = 0
    for onion in stored_onions:
        if re.search(VALID_ONION_RE, onion):
            beanstalk.put(onion, ttr=BEANSTALK_TTR)
            count += 1
    logging.debug("Loaded %d onions for scanning." % count)


# Handle a timeout from the onionscan process.
def handle_timeout(process, onion):
    global identity_lock

    identity_lock.clear()

    # kill the onionscan process
    try:
        process.kill()
        logging.debug('Killed the onionscan process.')
    except Exception as err:
        logging.warn(err)
        pass

    # Now we switch TOR identities to make sure we have a good connection
    with control.Controller.from_port(port=9051) as torcontrol:
        torcontrol.authenticate(TOR_CONTROL_PASSWORD)
        # send the signal for a new identity
        torcontrol.signal(stem.Signal.NEWNYM)
        # wait for the new identity to be initialized
        time.sleep(torcontrol.get_newnym_wait())
        logging.debug('Switched TOR identities.')

    identity_lock.set()
    return


# Runs onion scan as a child process.
def run_onionscan(onion):
    process = subprocess.Popen([PATH_TO_ONIONSCAN, "--jsonReport", "--simpleReport=false", onion],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    process_timer = threading.Timer(onion_master_list, handle_timeout, args=[process, onion])
    process_timer.start()
    stdout = process.communicate()[0]

    # we have received valid results so we can kill the timer
    if process_timer.is_alive():
        process_timer.cancel()
        return stdout
    return None


def process_results(onion_addr, results, bs):
    try:
        json_results = json.loads(results)
    except Exception as err:
        logging.warn(err)
        return None

    new_onions = set()
    for key in ['linkedSites', 'relatedOnionDomains', 'relatedOnionServices']:
        val = json_results.get(key)
        new_onions.update(val and val or [])

    for linked_onion in new_onions:
        if re.search(VALID_ONION_RE, linked_onion):
            bs.put(str(linked_onion), ttr=BEANSTALK_TTR)
    return json_results


def onionscan_worker(stop_event):
    beanstalk = beanstalkc.Connection(**BEANSTALK_SERVER)
    beanstalk.watch(ONION_QUEUE)
    redis_db = redis.StrictRedis(**REDIS_SERVER)
    es = elasticsearch.Elasticsearch()

    while not stop_event.isSet():
        identity_lock.wait(IDENTITY_LOCK_TIMEOUT)

        job = beanstalk.reserve(timeout=1)
        if not job:
            time.sleep(NO_JOB_SLEEP)
            logging.debug("No more jobs, quiting...")
            stop_event.set()
            continue

        onion_addr = job.body
        if not re.search(VALID_ONION_RE, onion_addr):
            logging.warn("Got invalid job: %s" % job.body)
            job.delete()
            continue

        # TODO(gerry): Check redis if onion has been scanned in X time frame
        logging.debug("Scanning: '%s'" % onion_addr)
        onionscan_results = run_onionscan(onion_addr)
        if onionscan_results is None:
            logging.debug("onionscan timed out scanning: '%s'. Requeuing job." % onion_addr)
            job.release()
            continue

        json_results = process_results(onion_addr, onionscan_results, beanstalk)
        if json_results:
            logging.debug("Done with '%s'" % onion_addr)
            redis_db.set(onion_addr, json_results.get('dateScanned'))
            # Throw it at redis so log stash can pick it up, do its thing, then send it to es
            redis_db.rpush('logstash', onionscan_results.decode('utf-8'))
            redis_db.incr('scanned')
            job.delete()
            continue
        logging.warn("Error with: '%s'." % onion_addr)


# TODO(gerry): Add cli args to:
#   populate BS from master list
#   saving of json files
#   number of workers
#   config file, etc
def main():
    global identity_lock
    LOG_FORMAT = '[%(levelname)s] (%(threadName)-10s) %(message)s'
    logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT,)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)
    logging.getLogger("stem").setLevel(logging.ERROR)

    #load_onion_list()

    stop_event = threading.Event()
    identity_lock = threading.Event()

    logging.debug("Starting workers...")
    for t in range(NUM_WORKERS):
        t = threading.Thread(name=onionscan_worker.func_name, target=onionscan_worker,
                             args=(stop_event,))
        t.setDaemon(True)
        t.start()

    logging.debug("Done starting workers, running...")
    identity_lock.set()

    try:
        while True and not stop_event.isSet():
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
    logging.debug("Exiting...")


if __name__ == '__main__':
    main()
