.. code-block:: shell

   $ cat /etc/commissaire/commissaire.conf
   {
     ...
     "storage-handlers": [
       {
         "name": "commissaire.store.kubestorehandler",
         ...
         "certificate_path": "/path/to/kube_clientside.crt",
         "certificate_key_path": "/path/to/kube_clientside.key"
       }
     ]
   }
