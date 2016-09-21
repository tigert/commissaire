.. code-block:: shell

   $ cat /etc/commissaire/commissaire.conf
   {
     ...
     "storage-handlers": [
       "name": "commissaire.store.kubestorehandler",
       ...
       "token": "$KUBERNETES_ACCESS_TOKEN"
     ]
   }
