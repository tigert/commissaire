# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

    # NOTE: Ordering matters! The commissaire box should be the
    #       the last box to start!

    # Development servers server.
    config.vm.define "servers" do |servers|
      servers.vm.box = "fedora/25-cloud-base"
      servers.vm.provider :libvirt do |domain|
       domain.memory = 1024
       domain.cpus = 1
      end
      servers.vm.network "private_network", ip: "192.168.152.101"
      config.vm.synced_folder ".", "/vagrant", disabled: true
      servers.vm.provision "shell", inline: <<-SHELL
        echo "==> Setting hostname"
        sudo hostnamectl set-hostname servers
        echo "===> Updating the system"
        sudo dnf update --setopt=tsflags=nodocs -y
        echo "===> Installing etcd and redis"
        sudo dnf install -y etcd redis
        echo "===> Configuring etcd"
        sudo gawk -i inplace '{ gsub("localhost", "0.0.0.0") }; /_INITIAL_|_ADVERTISE_/ { gsub("0.0.0.0", "192.168.152.101") }; { print }' /etc/etcd/etcd.conf
        echo "===> Starting etcd"
        sudo systemctl enable etcd
        sudo systemctl start etcd
        echo "===> Set flannel network"
        sudo etcdctl --endpoint=http://192.168.152.101:2379 set '/atomic01/network/config' '{"Network": "172.16.0.0/12", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}'
        echo "===> Configure redis"
        sudo sed -i "s/127.0.0.1/0.0.0.0/g" /etc/redis.conf
        sudo systemctl enable redis
        sudo systemctl start redis
      SHELL
    # End servers
    end

    # Development Kubernetes server.
    # NOTE: This must start after etcd.
    config.vm.define "kubernetes", autostart: false do |kubernetes|
      kubernetes.vm.box = "fedora/25-cloud-base"
      kubernetes.vm.provider :libvirt do |domain|
       domain.memory = 1024
       domain.cpus = 1
      end
      kubernetes.vm.network "private_network", ip: "192.168.152.102"
      config.vm.synced_folder ".", "/vagrant", disabled: true
      kubernetes.vm.provision "shell", inline: <<-SHELL
        echo "==> Setting hostname"
        sudo hostnamectl set-hostname kubernetes
        echo "===> Updating the system"
        sudo dnf update --setopt=tsflags=nodocs -y
        echo "===> Installing kubernetes"
        sudo dnf install -y kubernetes-master.x86_64
        echo "===> Configuring kubernetes"
        sudo sed -i "s|insecure-bind-address=127.0.0.1|insecure-bind-address=0.0.0.0|g" /etc/kubernetes/apiserver
        sudo sed -i "s|etcd-servers=http://127.0.0.1:2379|etcd-servers=http://192.168.152.101:2379|g" /etc/kubernetes/apiserver
        echo "===> Starting kubernetes"
        sudo systemctl enable kube-apiserver kube-scheduler kube-controller-manager
        sudo systemctl start kube-apiserver kube-scheduler kube-controller-manager
      SHELL
    # End kubernetes
    end


    # Development Node 1
    config.vm.define "fedora-cloud" do |node|
      node.vm.box = "fedora/25-cloud-base"
      node.vm.provider :libvirt do |domain|
       domain.memory = 1024
       domain.cpus = 1
      end
      node.vm.network "private_network", ip: "192.168.152.110"
      node.vm.provision "shell", inline: <<-SHELL
        echo "==> Setting hostname"
        sudo hostnamectl set-hostname fedora-cloud
        echo "===> Installing SSH keys"
        mkdir --parents /home/vagrant/.ssh
        cp /vagrant/features/id_rsa{,.pub} /home/vagrant/.ssh
        cat /home/vagrant/.ssh/id_rsa.pub >> /home/vagrant/.ssh/authorized_keys
        echo "===> Updating the system"
        sudo dnf update --setopt=tsflags=nodocs -y
        echo "===> Installing OS dependencies"
        sudo dnf install -y python
      SHELL
    # End fedora-cloud
    end

    # Development Node 1
    config.vm.define "fedora-atomic" do |node|
      node.vm.box = "fedora/25-atomic-host"
      node.vm.provider :libvirt do |domain|
       domain.memory = 1024
       domain.cpus = 1
      end
      node.vm.network "private_network", ip: "192.168.152.111"
      config.vm.synced_folder ".", "/vagrant", disabled: true
      config.vm.synced_folder ".", "/home/vagrant/sync", type: "sshfs"
      node.vm.provision "shell", inline: <<-SHELL
        echo "==> Setting hostname"
        sudo hostnamectl set-hostname fedora-atomic
        echo "===> Installing SSH keys"
        mkdir --parents /home/vagrant/.ssh
        cp /home/vagrant/sync/features/id_rsa{,.pub} /home/vagrant/.ssh
        cat /home/vagrant/.ssh/id_rsa.pub >> /home/vagrant/.ssh/authorized_keys
      SHELL
    # End fedora-atomic
    end

  # Development commissaire server and services
  # NOTE: This must start after etcd.
  config.vm.define "commissaire", primary: true, autostart: false do |commissaire|
    commissaire.vm.box = "fedora/25-cloud-base"
    commissaire.vm.provider :libvirt do |domain|
     domain.memory = 1024
     domain.cpus = 1
    end
    commissaire.vm.network "private_network", ip: "192.168.152.100"
    config.vm.synced_folder ".", "/vagrant", disabled: true
    config.vm.synced_folder ".", "/vagrant/commissaire", type: "sshfs"
    config.vm.synced_folder "../commissaire-http", "/vagrant/commissaire-http",  type: "sshfs"
    config.vm.synced_folder "../commissaire-service", "/vagrant/commissaire-service", type: "sshfs"
    commissaire.vm.provision "shell", inline: <<-SHELL
      echo "==> Setting hostname"
      sudo hostnamectl set-hostname commissaire
      echo "===> Updating the system"
      sudo dnf update -y
      echo "===> Installing OS dependencies"
      sudo dnf install -y --setopt=tsflags=nodocs rsync openssh-clients redhat-rpm-config python3-virtualenv gcc libffi-devel openssl-devel git nfs-utils etcd
      echo "===> Setting up virtualenv"
      virtualenv-3 commissaire_env
      echo "===> Installing commissaire"
      . commissaire_env/bin/activate && pip install -U -r /vagrant/commissaire/test-requirements.txt
      . commissaire_env/bin/activate && pip install -e /vagrant/commissaire/
      echo "===> Installing commissaire-http"
      . commissaire_env/bin/activate && pip install -U -r /vagrant/commissaire-http/test-requirements.txt
      . commissaire_env/bin/activate && pip install -e /vagrant/commissaire-http/
      echo "===> Installing commissaire-service"
      . commissaire_env/bin/activate && pip install -U -r /vagrant/commissaire-service/test-requirements.txt
      . commissaire_env/bin/activate && pip install -e /vagrant/commissaire-service/

      echo "===> Setting up commissaire-server to autostart"
      sudo cp /vagrant/commissaire-http/conf/systemd/commissaire-server.service /etc/systemd/system/commissaire-server.service
      sudo chmod 644 /etc/systemd/system/commissaire-server.service
      sudo mkdir --parents /etc/commissaire
      sudo cp /vagrant/commissaire-http/conf/commissaire.conf /etc/commissaire/commissaire.conf
      sudo sed -i 's|"listen-interface": "127.0.0.1"|"listen-interface": "0.0.0.0"|g' /etc/commissaire/commissaire.conf
      sudo sed -i 's|"bus-uri": "redis://127.0.0.1:6379/"|"bus-uri": "redis://192.168.152.101:6379/"|g' /etc/commissaire/commissaire.conf
      sudo sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c ". /home/vagrant/commissaire_env/bin/activate \\&\\& commissaire-server -c /etc/commissaire/commissaire.conf"|' /etc/systemd/system/commissaire-server.service
      sudo sed -i 's|Type=simple|\&\\nWorkingDirectory=/vagrant|' /etc/systemd/system/commissaire-server.service

      echo "===> Populating ETCD storage"
      . commissaire_env/bin/activate && export ETCDCTL_ENDPOINTS="http://192.168.152.101:2379" && bash /vagrant/commissaire/tools/etcd_init.sh

      echo "===> Setting up commissaire-storage service to autostart"
      sudo cp /vagrant/commissaire-service/conf/storage.conf /etc/commissaire/storage.conf
      sudo cp /vagrant/commissaire-service/conf/systemd/commissaire-storage.service /etc/systemd/system/commissaire-storage.service
      sudo sed -i 's|"server_url": "http://127.0.0.1:2379"|"server_url": "http://192.168.152.101:2379"|g' /etc/commissaire/storage.conf
      sudo sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c ". /home/vagrant/commissaire_env/bin/activate \\&\\& commissaire-storage-service -c /etc/commissaire/storage.conf --bus-uri redis://192.168.152.101:6379"|' /etc/systemd/system/commissaire-storage.service

      echo "===> Setting up commissaire-clusterexec service to autostart"
      sudo cp /vagrant/commissaire-service/conf/systemd/commissaire-clusterexec.service /etc/systemd/system/commissaire-clusterexec.service
      sudo sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c ". /home/vagrant/commissaire_env/bin/activate \\&\\& commissaire-clusterexec-service --bus-uri redis://192.168.152.101:6379"|' /etc/systemd/system/commissaire-clusterexec.service

      echo "===> Setting up commissaire-investigator service to autostart"
      sudo cp /vagrant/commissaire-service/conf/systemd/commissaire-investigator.service /etc/systemd/system/commissaire-investigator.service
      sudo sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c ". /home/vagrant/commissaire_env/bin/activate \\&\\& commissaire-investigator-service --bus-uri redis://192.168.152.101:6379"|' /etc/systemd/system/commissaire-investigator.service

      echo "===> Setting up commissaire-watcher service to autostart"
      sudo cp /vagrant/commissaire-service/conf/systemd/commissaire-watcher.service /etc/systemd/system/commissaire-watcher.service
      sudo sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c ". /home/vagrant/commissaire_env/bin/activate \\&\\& commissaire-watcher-service --bus-uri redis://192.168.152.101:6379"|' /etc/systemd/system/commissaire-watcher.service

      echo "===> Setting up commissaire-containermgr service to autostart"
      sudo cp /vagrant/commissaire-service/conf/containermgr.conf /etc/commissaire/containermgr.conf
      sudo cp /vagrant/commissaire-service/conf/systemd/commissaire-containermgr.service /etc/systemd/system/commissaire-containermgr.service
      sudo sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c ". /home/vagrant/commissaire_env/bin/activate \\&\\& commissaire-containermgr-service --bus-uri redis://192.168.152.101:6379"|' /etc/systemd/system/commissaire-containermgr.service

      echo "===> Starting commissaire-server"
      sudo systemctl daemon-reload
      sudo systemctl enable commissaire-server
      sudo systemctl start commissaire-server

      echo "===> Starting commissaire-storage service"
      sudo systemctl enable commissaire-storage
      sudo systemctl start commissaire-storage

      echo "===> Starting commissaire-clusterexec service"
      sudo systemctl enable commissaire-clusterexec
      sudo systemctl start commissaire-clusterexec

      echo "===> Starting commissaire-investigator service"
      sudo systemctl enable commissaire-investigator
      sudo systemctl start commissaire-investigator

      echo "===> Starting commissaire-watcher service"
      sudo systemctl enable commissaire-watcher
      sudo systemctl start commissaire-watcher

      echo "===> Starting commissaire-containermgr"
      sudo systemctl daemon-reload
      sudo systemctl enable commissaire-containermgr
      sudo systemctl start commissaire-containermgr

    SHELL
  # End commissaire
  end

# End config
end
