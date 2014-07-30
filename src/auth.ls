# ISSUES
# - every site needs its own credentials for 3rd party auth

require! {
  \async
  \bcrypt
  \crypto
  \debug
  \nodemailer
  \passport
  \passport-local
  \passport-facebook
  \passport-twitter
  \passport-google-oauth
  h: \./server-helpers
  pg: \./postgres
  passport.Passport
}

log = debug 'auth'

# site-aware passport middleware wrappers
export mw =
  initialize: (req, res, next) ~>
    domain = res.vars.site?current_domain
    err, passport <~ @passport-for-domain domain
    if err then return next(err)
    if passport
      passport.mw-initialize(req, res, next)
    else
      next(404)
  session: (req, res, next) ~>
    site_id = res.vars.site?id
    domain = res.vars.site?current_domain
    err, passport <~ @passport-for-domain domain
    if err then return next err
    if passport
      passport.mw-session req, res, next
    else
      next(404)

export hash = (s) ->
  bcrypt.hash-sync s, 5

export valid-password = (user, password) ->
  return false if not user or not password
  bcrypt.compare-sync password, user?auths?local?password

export verify-string = ->
  buffer = crypto.random-bytes(32)
  char = (c) ->
    c2 = Math.floor(c / 10.24) # fp-math? really??
    c3 = c2 + 97
    String.from-char-code c3
  [ char v for v,i in buffer ].join ''

export unique-hash = (field, site-id, cb) ->
  # if all these fail, you've won the lottery
  # one should pass,
  # usually the first
  candidates = [ verify-string! for i from 1 to 10 ] # it's too bad this couldn't be an infinite lazy list

  unique = (v, cb) ->
    (err, found-alias) <- pg.procs.alias-unique-hash field, site-id, v
    if err then return cb err
    if found-alias
      cb false
    else
      cb true

  async.detect candidates, unique, (uv) ->
    cb null, uv

export registration-email-template-text = """
Welcome to {{site-name}}, {{user-name}}!

To verify your account, please visit:

  https://{{site-domain}}/auth/verify/{{user-verify}}

"""

export registration-email-template-html = """
"""

export recovery-email-template-text = """
Hello,

To recover your password for {{site-name}}, please visit:

  https://{{site-domain}}/\#recover={{user-forgot}}

"""

export recovery-email-template-html = """
"""

#
export send-registration-email = (user, site, cb) ->
  vars =
    # I have to quote the keys so that the template-vars with dashes will get replaced.
    "site-name"   : site.name
    "site-domain" : site.current_domain
    "user-name"   : user.name
    "user-verify" : user.verify
  email =
    from    : "noreply@#{site.current_domain}"
    to      : user.email
    subject : "Welcome to #{site.name}"
    text    : h.expand-handlebars registration-email-template-text, vars
  h.send-mail email, cb

export send-recovery-email = (user, site, cb) ->
  vars =
    # I have to quote the keys so that the template-vars with dashes will get replaced.
    "site-name"   : site.name
    "site-domain" : site.current_domain
    "user-name"   : user.name
    "user-forgot" : user.forgot
  email =
    from    : "noreply@#{site.current_domain}"
    to      : user.email
    subject : "[#{site.name}] Password Recovery"
    text    : h.expand-handlebars recovery-email-template-text, vars
  h.send-mail email, cb

export send-invite-email = (site, user, new-user, message, cb) ->
  vars =
    # I have to quote the keys so that the template-vars with dashes will get replaced.
    "site-name"   : site.name
    "site-domain" : site.current_domain
    "user-email"  : new-user.email
    "user-verify" : new-user.verify
    "message"     : message
  tmpl = """
    {{message}}
    
    Follow this link and login:
     https://{{site-domain}}/auth/invite/{{user-verify}}
  """
  email =
    from    : "#{user.name}@#{site.current_domain}"
    to      : user.email
    subject : "Invite to #{site.name}!"
    text    : h.expand-handlebars tmpl, vars
  log email
  h.send-mail email, cb

export user-forgot-password = (user, cb) ->
  err, hash <- unique-hash \forgot, user.site_id
  if err then return cb err

  user.forgot = hash
  err <- db.aliases.update { forgot: hash }, { user_id: user.id, site_id: user.site_id }

  cb null, user

export set-login-token = (user, cb) ->
  err, hash <- unique-hash \login_token, user.site_id
  if err then return cb err

  newly-created = false

  # autovivify alias
  maybe-create-alias = (cb) ->
    err, alias <- db.aliases.select-one { user_id: user.id, site_id: user.site_id }
    if err then return cb err
    if not alias
      newly-created := true
      console.warn \creating-alias
      err, alias <- db.aliases.select-one { user_id: user.id, site_id: 1 }
      if err then return cb err
      if not alias then return cb(new Error("user #{user.id} has no alias for site_id 1"))
      err, unique-name <- db.unique-name { name: alias.name, site_id: user.site_id }
      db.aliases.add-to-user user.id, [user.site_id], { name: unique-name, photo: \/images/profile.png }, cb
    else
      cb null

  err <- maybe-create-alias
  if err then return cb err

  user.login_token = hash
  user.choose-username = newly-created
  err <- db.aliases.update { login_token: hash }, { user_id: user.id, site_id: user.site_id }
  if err then return cb err

  cb null, user

export create-passport = (domain, cb) ->
  (err, site) <~ db.site-by-domain domain
  if err then return cb(err)

  current-domain = find (-> it.name == site.current_domain), site.domains
  if not current-domain then return cb(new Error("domain object for #{site.current_domain} could not be found"))
  config = current-domain.config

  pass = new Passport
  cvars = global.cvars

  # middleware functions for this passport
  pass.mw-initialize = pass.initialize()
  pass.mw-session    = pass.session()

  pass.serialize-user (user, done) ~>
    log \user, \xxx, user
    parts = "#{user.name}:#{user.site_id}"
    done null, parts

  pass.deserialize-user (parts, done) ~>
    log \parts, parts
    [name, site_id] = parts.split ':'
    (err, user) <~ db.usr {name, site_id}
    if err then return cb err
    if name and site_id
      done null, user
    else
      done new Error("bad cookie #{parts}")

  pass.use new passport-local.Strategy (email, password, done) ~>
    console.log email, site.id
    (err, user) <~ db.users.by-email-and-site email, site.id
    #console.log \db.users.by-email-and-site, user
    errors = [ "Invalid login" ] # vague message on purpose
    if err then return done(err)
    if not user
      log 'no user'
      return done(null, false, { errors })
    if not valid-password(user, password)
      log 'invalid password', password, user
      return done(null, false, { errors })
    # XXX the following lines force verification
    #if not user.verified
    #  log 'unverified user', user
    #  return done(null, false, { type: \unverified-user, errors: ['Unverified user'], email: user.email })
    log 'ok'
    done(null, user)

  facebook-options =
    client-ID     : config?facebook-client-id     or \x
    client-secret : config?facebook-client-secret or \x
    callback-URL  : "https://#{domain}/auth/facebook/return"
  pass.use new passport-facebook.Strategy facebook-options, (access-token, refresh-token, profile, done) ->
    log 'facebook profile', profile
    err, name <- db.unique-name name: profile.display-name, site_id: site.id
    if err then return cb err
    err, vstring <- unique-hash \verify, site.id
    if err then return cb err
    u =
      type    : \facebook
      id      : profile.id
      profile : profile._json
      site_id : site.id
      name    : name
      verify  : vstring
    (err, user) <- db.find-or-create-user u
    log 'err', err if err
    done(err, user)

  twitter-options =
    consumer-key    : config?twitter-consumer-key    or \x
    consumer-secret : config?twitter-consumer-secret or \x
    callback-URL    : "https://#{domain}/auth/twitter/return"
  pass.use new passport-twitter.Strategy twitter-options, (access-token, refresh-token, profile, done) ->
    log 'twitter profile', profile
    err, name <- db.unique-name name: profile.display-name, site_id: site.id
    if err then return cb err
    err, vstring <- unique-hash \verify, site.id
    if err then return cb err
    u =
      type    : \twitter
      id      : profile.id
      profile : profile._json
      site_id : site.id
      name    : name
      verify  : vstring
    (err, user) <- db.find-or-create-user u
    log 'err', err if err
    done(err, user)

  google-options =
    client-ID     : config?google-consumer-key    or \x
    client-secret : config?google-consumer-secret or \x
    callback-URL  : "https://#{domain}/auth/google/return"
  pass.use new passport-google-oauth.OAuth2Strategy google-options, (access-token, refresh-token, profile, done) ->
    log 'google profile', profile
    err, name <- db.unique-name name: profile.display-name, site_id: site.id
    if err then return cb err
    err, vstring <- unique-hash \verify, site.id
    if err then return cb err
    # TODO - store profile.picture if available
    u =
      type    : \google
      id      : profile.id
      profile : profile._json
      site_id : site.id
      name    : name
      verify  : vstring
    log \u, u
    (err, user) <- db.find-or-create-user u
    log 'err', err if err
    done(err, user)

  cb(null, pass)

export passports = {}

export passport-for-domain = (domain, cb) ~>
  if @passports[domain]
    #log "found cached passport for #domain"
    cb null, @passports[domain]
  else
    err, pass <~ @create-passport domain
    if err then return cb err
    if pass
      #log "created new passport for #domain"
      @passports[domain] = pass
      cb null, pass
    else
      #log "could not create passport for #domain"
      cb new Error("Could not create Passport for #domain.")

# vim:fdm=indent
