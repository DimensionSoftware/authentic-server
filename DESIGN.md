# Design

## The User API

`authentic-server` allows an application to provide an object that tells it how to query and manipulate
the user database.  This makes `authentic-server` database agnostic which is a useful attribute for
a general authentication system to have.

As long as this object conforms to the following API, `authentic-server` can provide authentication for
your app.

### `User.find(options, cb)`

### `User.findOrCreate(options, cb)`

### `User.save(user, cb)`


## Routes

### POST /login

### POST /once

### GET /once-admin ?

### POST /register

### POST /choose-username

### GET /user

### GET /verify/:v

### GET /invite/:v

### POST /forgot

### POST /forgot-user

### POST /reset-password

### POST /resend

### GET /:oauth-provider

### GET /:oauth-provider/return

### GET /:oauth-provider/finish

### GET /logout
