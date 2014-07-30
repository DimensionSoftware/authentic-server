require! {
  fs
  async
  jade
  querystring
  url
  sioa: \socket.io-announce
  pg:   \./postgres
  auth: \./auth
  __: lodash
}

announce = sioa.create-client!

{is-editing, is-admin, is-auth} = require \./path-regexps

@login = (req, res, next) ->
  site      = res.vars.site
  domain    = site.current_domain
  site-room = site.id
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  if passport
    #console.warn "domain", domain unless env is \production

    auth-response = (err, user, info) ->
      # can't be showing passwords in production logs :D
      #console.warn \auth-response, err, user, info unless env is \production
      if err then return next(err)
      if not user then return res.json { success: false } <<< info

      extra = {}

      maybe-join-site = if user and not user.name
        (cb) ->
          console.error "joining site for first time"
          # grab default user (site_id 1)
          email = req.body.username
          err, default-alias <- db.aliases.most-recent-for-user user.id
          if err then return cb err

          # create unique name based on default user's name
          err, unique-name <- db.unique-name name: default-alias.name, site_id: site.id
          if err then return cb err

          # create an alias for this site
          alias =
            user_id : default-alias.user_id
            site_id : site.id
            name    : unique-name
            rights  : {}
            photo   : default-alias.photo
          err <- db.alias-create-preverified alias
          if err then cb err

          # make client choose alias.name
          extra.choose-name = true
          extra.name        = unique-name
          new-user = user <<< alias
          cb null, new-user
      else
        (cb) -> cb null, user

      err, maybe-new-user <- maybe-join-site
      #console.log \maybe-join-site err
      if err then res.json success: false

      req.login maybe-new-user, (err) ->
        if err then return next(err)
        #console.warn "emitting enter-site #{JSON.stringify(user)}" unless env is \production
        announce.in(site-room).emit \enter-site, user
        err <- db.aliases.update-last-activity-for-user user
        if err then return next(err)
        res.json { success: true } <<< extra

    passport.authenticate('local', auth-response)(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send \500, 500

@once = (req, res, next) ->
  token = req.body.token
  site  = res.vars.site
  err, r <- db.authenticate-login-token site.id, token
  console.warn \authenticate-login-token, [err, r]
  if err then return next err
  if r
    req.session?passport?user = "#{r.name}:#{site.id}"
    res.json success: true, choose-name: !!(r.created_human?match /Just now/i), name: r.name
  else
    res.json success: false

@once-setup = (req, res, next) ->
  try site-id = parse-int req.query.site_id
  return unless site-id # guard
  user =
    id      : req.user.id
    site_id : site-id
  err, r <- auth.set-login-token user
  if err then return next err
  if r
    res.json success: true, token: r.login_token
  else
    res.json success: false

@once-admin = (req, res, next) ->
  res.render \once-admin

@register = (req, res, next) ~>
  site     = res.vars.site
  domain   = site.current_domain
  passport = auth.passport-for-domain[domain]

  if res.locals.invite-only then next 404; return # registration disabled

  # TODO more validation
  req.assert \username .not-empty!is-alphanumeric!  # .len(min, max) .regex(/pattern/)
  req.assert \password .not-empty!  # .len(min, max) .regex(/pattern/)
  req.assert \email .is-email!

  err, user <~ db.users.email-in-use email:req.body.email
  if err
    return res.json success:false, errors:[err]
  if user
    console.log \email-exists, err, user, req.body.email, site.id
    return res.json success:false, errors:["This email address has already been registered."]

  err, alias <~ db.aliases.select-one site_id: site.id, name: req.body.username
  if err
    return res.json success:false, errors:[err]
  if alias
    console.log \name-exists err, alias, req.body.username, site.id
    return res.json success:false, errors:["This name has already been registered on this site."]

  if errors = req.validation-errors!
    console.warn errors
    res.json {errors}
  else
    username = req.body.username
    password = req.body.password
    email    = req.body.email
    (err, u) <~ register-local-user site, username, password, email
    if err
      # FIXME possible email abuse if if attacker is able to create accounts
      if err?verify # err is existing user, so ...
        console.warn 'user exists:', err, site
        <~ auth.send-registration-email err, site # resend!
        res.json success:false, errors:[msg:'Resent verification email!']
      else
        # default error situation
        return res.json success:false, errors:[ err.msg ]

    done = ~>
      auth.send-registration-email u, site, (err, r) ->
        console.warn 'registration email', err, r
      #res.json success:true, errors:[]   # <- just register

      err <~ db.aliases.update-last-activity-for-user u
      if err then next err

      req.body.username = email           # give passport what it wants, where it wants it
      unless site.config.private
        @login req, res, next             # <- autologin
      else
        res.json {+success}
                                          # pick one
    done!

do-verify = (req, res, next) ~>
  v    = req.param \v
  site = res.vars.site
  err, r <- db.verify-user site.id, v
  if err then return next err
  if r
    req.session?passport?user = "#{r.name}:#{site.id}" # XXX
    if res.vars.is-invite or site.config.private 
      res.redirect \/#choose
    else
      res.redirect \/#validate
  else
    res.redirect \/#invalid
@verify = (req, res, next) -> do-verify req, res, next
@invite = (req, res, next) ->
  if req.user
    res.redirect "/\#invalid=#{req.user.name.replace /@.*/, ''}"
  else
    res.vars.is-invite = true
    do-verify req, res, next

@forgot = (req, res, next) ->
  db    = pg.procs
  site  = res.vars.site
  email = req.body.email

  if not email
    res.json success: false, errors: [ 'Blank email' ]
    return

  err, user <- db.users.by-email-and-site email, site.id
  if err
    res.json success: false, errors: [ err ]
    return

  if user
    err, user-forgot <- auth.user-forgot-password user
    if err
      res.json success: false, errors: [ err ]
      return

    err <- auth.send-recovery-email user-forgot, site
    if err
      res.json success: false, errors: [ err ]
    else
      res.json success: true
  else
    res.json success: false, errors: [ 'User not found' ]

@forgot-user = (req, res, next) ->
  site = res.vars.site
  hash = req.body.forgot
  err, user <- db.usr forgot: hash, site_id: site.id
  if err
    return res.json success: false, errors: [ err ]
  if user
    res.json success: true
  else
    res.json success: false, errors: [ "User not found" ]

@reset-password = (req, res, next) ->
  site = res.vars.site
  hash = req.body.forgot
  password = req.body.password

  err, user <- db.usr forgot: hash, site_id: site.id
  if err
    console.warn \usr, err
    return res.json success: false, errors: [ err ]

  if user
    auths-local = user.auths.local
    auths-local.password = auth.hash password
    # TODO if alias doesn't exist, ask for username and insert (register)
    err <- db.auths.update { profile: auths-local }, { type: \local, user_id: user.id }
    if err
      console.warn \auths-update, err
      return res.json success: false, errors: [ err ]

    err <- db.alias-blank user
    if err
      console.warn \alias-blank, err
      return res.json success: false, errors: [ err ]

    res.json success: true
  else
    console.warn \usr, "User not found"
    res.json success: false, errors: [ "User not found" ]

# resend verification email
@resend = (req, res, next) ->
  site  = res.vars.site
  email = req.body.email

  err, user <- db.users.by-email-and-site email, site.id
  if err then return res.json success: false, when: \db.usr

  err, verify <- auth.unique-hash \verify, site.id
  if err then return res.json success: false, when: \auth.unique-hash
  user.verify = verify

  # TODO if alias doesn't exist, ask for username and insert (register)
  err <- db.aliases.update { verify }, { user_id: user.id, site_id: site.id }
  if err then return res.json success: false, when: \db.aliases.update

  err <- auth.send-registration-email user, site
  if err then return res.json success: false, when: \auth.send-registration-email

  res.json success: true

# XXX users may change user names any amount of times by avoiding the ui
# - in the future, consider adding field to aliases to count # of changes,
# - then build a setting in general admin to user-specify
@choose-username = (req, res, next) ->
  user = req.user
  site = res.vars.site
  if not user then return res.json success:false
  db   = pg.procs
  usr  =
    user_id : user.id
    site_id : user.site_id
    name    : req.body.username
  (err, r) <- db.change-alias usr
  if err then return res.json {success:false, msg:'Name in-use!'}

  maybe-add-aliases = if site.id is 1
    (cb) ->
      cvars = global.cvars
      default-site-ids = cvars.default-site-ids |> filter (-> it is not user.site_id)
      db.aliases.add-to-user user.id, default-site-ids, { name: req.body.username, +verified }, cb
  else
    (cb) -> cb null

  err <- maybe-add-aliases
  if err then return res.json success: false

  req.session?passport?user = "#{req.body.username}:#{user.site_id}"
  res.json success:true

@login-facebook = (req, res, next) ->
  domain = res.vars.site.current_domain
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  if passport
    req.session.origin = req.query.origin
    passport.authenticate('facebook')(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send 500, \500

@login-facebook-return = (req, res, next) ->
  domain = res.vars.site.current_domain
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  if passport
    passport.authenticate('facebook', { success-redirect: '/auth/facebook/finish', failure-redirect: '/auth/facebook/finish?fail=1' })(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send \500, 500

auth-finisher = (req, res, next) ->
  user = req.user
  origin = req.session.origin
  host = if process.env.NODE_ENV is \production then \powerbulletin else \pb
  err <- db.aliases.update-last-activity-for-user user
  if err then return next err
  res.send """
  <script type="text/javascript" src="https://muscache.#host.com/local/jquery-1.10.2.min.js"></script>
  <script type="text/javascript" src="https://muscache.#host.com/local/jquery.ba-postmessage.min.js"></script>
  <script type="text/javascript">
    $.postMessage("login", "#origin", window.opener);
    window.close();
  </script>
  """

@login-facebook-finish = auth-finisher

@login-google = (req, res, next) ->
  domain = res.vars.site.current_domain
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  scope    = 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'

  if passport
    req.session.origin = req.query.origin
    passport.authenticate('google', {scope})(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send \500, 500

@login-google-return = (req, res, next) ->
  domain = res.vars.site.current_domain
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  if passport
    passport.authenticate('google', { success-redirect: '/auth/google/finish', failure-redirect: '/auth/google/finish?fail=1' })(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send \500, 500

@login-google-finish = auth-finisher

@login-twitter = (req, res, next) ->
  domain = res.vars.site.current_domain
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  if passport
    req.session.origin = req.query.origin
    passport.authenticate('twitter')(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send \500, 500

@login-twitter-return = (req, res, next) ->
  domain = res.vars.site.current_domain
  err, passport <- auth.passport-for-domain domain
  if err then return next(err)
  if passport
    passport.authenticate('twitter', { success-redirect: '/auth/twitter/finish', failure-redirect: '/auth/twitter/finish?fail=1' })(req, res, next)
  else
    console.warn "no passport for #{domain}"
    res.send \500, 500

@login-twitter-finish = auth-finisher

@logout = (req, res, next) ->
  user = req.user
  user_id = user?id
  site_id = res.vars.site.id
  if req.user # guard
    req.logout!
    err <- db.aliases.update-last-activity-for-user { user_id, site_id }
    if err then return next err
    redirect-url = url.parse(req.param(\redirect-url) or req.header(\Referer) or '/').pathname
    if req.headers['x-requested-with'] # jquery doesn't need another page
      res.json {+success}
    else
      res.redirect redirect-url.replace(is-editing, '').replace(is-admin, '').replace(is-auth, '')
  else
    res.redirect '/'

@user = (req, res, next) ->
  req.user ||= null
  if req.user
    res.json __.omit(req.user, \auths)
  else
    res.json null

@no-cache = (req, res, next) ->
  caching-strategies.nocache res
  next!

@apply-to = (app, mw) ->
  app.all  /^\/auth\/.*$/,              @no-cache
  app.post '/auth/login',           mw, @login
  app.post '/auth/once',            mw, @once
  app.get  '/auth/once-admin'       mw, @once-admin
  app.post '/auth/register',        mw, @register
  app.post '/auth/choose-username', mw, @choose-username
  app.get  '/auth/user',            mw, @user
  app.get  '/auth/verify/:v',       mw, @verify
  app.get  '/auth/invite/:v',       mw, @invite
  app.post '/auth/forgot',          mw, @forgot
  app.post '/auth/forgot-user'      mw, @forgot-user
  app.post '/auth/reset-password'   mw, @reset-password
  app.post '/auth/resend'           mw, @resend

  app.get  '/auth/facebook',        mw, @login-facebook
  app.get  '/auth/facebook/return', mw, @login-facebook-return
  app.get  '/auth/facebook/finish', mw, @login-facebook-finish

  app.get  '/auth/google',          mw, @login-google
  app.get  '/auth/google/return',   mw, @login-google-return
  app.get  '/auth/google/finish',   mw, @login-google-finish

  app.get  '/auth/twitter',         mw, @login-twitter
  app.get  '/auth/twitter/return',  mw, @login-twitter-return
  app.get  '/auth/twitter/finish',  mw, @login-twitter-finish

  app.get  '/auth/logout',          mw, @logout
