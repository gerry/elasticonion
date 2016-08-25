# Elastic Onion
Onionscan backed by elasticsearch.

Fair warning, I've been on a get all the X into ES kick lately, and this is just 
the latest value of X. It was also hacked together in a late caffeine fueled night.
Don't expect it to be too stable, but it runs pretty well for me and has provided 
some fun/interesting data to build dashboards with or build out other scans from ES.

I blame @jms_dot_py and 
this [post](http://www.automatingosint.com/blog/2016/07/dark-web-osint-with-python-and-onionscan-part-one/) of his for giving me the idea.

#### Install requirements
These notes should be enough to show you what you need. Installing beanstalk, redis, elasticsearch, logstash, kibana, their prerequisites and some python libraries.

```
$ sudo apt-get install tor git bison libexif-dev screen python-pip golang
$ sudo apt-get install beanstalkd
$ pip install stem pyyaml beanstalkc
$ go get github.com/s-rah/onionscan
$ mkdir ~/gocode
$ echo 'GOLANG=~/gocode' >> .bash_profile
$ tor --hash-password mysecrettorpassword
$ sudo bash -c 'cat << EOF >> /etc/tor/torrc
> ControlPort 9051
> ControlListenAddress 127.0.0.1
> HashedControlPassword 16:5A4ED0F4254848636082D9CBB95379E8BBAD2245D24A091B230B661D7A
> EOF'
$ sudo service tor restart
$ sudo apt-get install redis-server
$ pip install redis
$ sudo add-apt-repository ppa:webupd8team/java -y
$ sudo apt-get update && sudo apt-get install oracle-java8-installer -y
$ wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
$ echo "deb https://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
$ sudo apt-get update && sudo apt-get install elasticsearch -y
$ sudo /bin/systemctl daemon-reload
$ sudo /bin/systemctl enable elasticsearch.service
$ pip install elasticsearch
$ echo "deb http://packages.elastic.co/kibana/4.4/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-4.4.x.list
$ sudo apt-get update && sudo apt-get -y install kibana
$ sudo service kibana start
$ echo 'deb http://packages.elastic.co/logstash/2.2/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash-2.2.x.list
$ sudo apt-get update && sudo apt-get install logstash -y
$ sudo cp logstash.conf /etc/logstash/conf.d/elasticonion.conf'
$ sudo service logstash restart
```