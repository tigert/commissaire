Installation instructions
=========================

The following instructions will setup a development environment
for commissaire.

If something does not work as expected, please create an issue or
propose a PR.


## Prepare environment
The environment can be installed on a base Fedora 24 installation.

```
sudo dnf update -y
sudo dnf install -y etcd redis
sudo dnf install -y @development-tools redhat-rpm-config
sudo dnf install -y python3 python3-virtualenv
```

```
$ systemctl enable etcd redis
$ systemctl start etcd redis
```


## Pull repositories
Commissaire consists of several projects that either provide
common code or the actual services.

```
mkdir commissaire-projects
cd commissaire-projects
git clone https://github.com/projectatomic/commissaire
git clone https://github.com/projectatomic/commissaire-service
git clone https://github.com/projectatomic/commissaire-http
git clone https://github.com/projectatomic/commctl
```

After this we will install each project to setup a development
environment.


### Create VirtualEnv
```
virtualenv-3.5 devel
. devel/bin/activate
```

Continue executing the following commands in the virtualenv you just created.


## Install Commissaire
```
cd commissaire
pip install -e .
popd
```


### Install Commissaire Service
```
cd commissaire-service
pip install -e .
tools/etcd_init.sh
```

Edit your storage configuration to point to your etcd instance
```
cp conf/storage.conf mystorage.conf
```
Note: point server_url to http://127.0.0.1:2379 (not https)


Start the service
```
commissaire-storage-service -c mystorage.conf &
popd
```

### Install Commissaire Server
```
cd commissaire-http
pip install -e .  # Install commissaire-http into the virtualenv
```

Edit the configuration to point to your redis instance
```
cp conf/commissaire.conf config.conf
```
Note: if locally installed you do not need to change anything

Start the service
```
commissaire-server -c config.conf &
popd
```

#### Run testcases for Commissaire Server
Note that you can use `tox` to run testcases for this project.

Install using

```
pip install tox
```

and then, from the `commissaire-http` folder, run the following
command:

```
tox -v -e py35
```


## Verification
After this the API will be available at `http://127.0.0.1:8000/`. To
verify it works, we will use the initial user `a` with pass `a`.

```
curl -u "a:a" -X GET http://127.0.0.1:8000/api/v0/clusters/
```


## Using `commctl`

```
cd commctl
pip install -e .
popd
```

Edit the configuration:
```
vi ~/.commissaire.json
```

    {
        "username": "a",
        "password": "a",
        "endpoint": "http://127.0.0.1:8000"
    }

To query the known clusters:

```
commctl cluster list
```

In our case this should now return `No object found`
