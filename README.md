basic proof of concept of utilising a central web service to request private and public ssh keys to gain access to ssh services.

generic idea is that we keep tight control of which ssh keypairs are allowed to be used to access s3df. we only allow ssh keys to obtain access. users have to periodically authenticate against this web app to 'refresh' the keys - meaning that if they do not, the keys are no longer valid. we can therefore control the validity of the keypair (since we can expire the authorized_keys).

i guess we could also do some key signing to be fancy with a validUntil.

this requires that sshd be configured to utilise `AuthorizedKeysCommand` to do something as simple as 

```
curl -sf https://<this-server>/authorized_keys/$1
```

and then add
```
AuthorizedKeysCommand /usr/local/bin/fetch_authorized_keys.sh
AuthorizedKeysCommandUser nobody
```
to sshd_config