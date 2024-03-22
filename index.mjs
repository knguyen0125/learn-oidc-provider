import express from 'express'
import Provider from 'oidc-provider'
import MemoryAdapter from "./adapter.mjs";

const provider = new Provider('http://localhost:3000', {
  adapter: MemoryAdapter,
  clients: [{
    client_id: 'foo',
    client_secret: 'bar',
    redirect_uris: ['https://oauth.pstmn.io/v1/callback'],
    grant_types: ['authorization_code'],
    scope: 'openid profile api:read api:write',
  }],
  async findAccount(ctx, id) {
    return {
      accountId: id,
      async claims() {
        return {sub: id}
      },
    }
  },
  features: {
    clientCredentials: {
      enabled: true
    },
    devInteractions: {
      enabled: false
    },
    introspection: {
      enabled: true
    },
    resourceIndicators: {
      enabled: true,
      getResourceServerInfo(ctx, resourceIndicator, client) {
        console.log(ctx, resourceIndicator, client)
        return {
          scope: 'api:read api:write',
          accessTokenTTL: 5 * 60,
          accessTokenFormat: 'jwt',
          jwt: {
            sign: { alg: 'RS256'}
          }
        }
      }
    }
  },
  cookies: {
    keys: ['cookie secret']
  },
  interactions: {
    url(ctx, interaction) {
      return `/interactions/${interaction.uid}`
    }
  },
})

const app = express()

app.set('view engine', 'hbs')


app.use((err, req, res, next) => {
  console.log(req)

  next()
})

app.use(express.json())
app.use(express.urlencoded({extended: true}))

app.get('/', (req, res) => {
  res.send('hi')
})

app.get('/interactions/:uid', async (req, res) => {
  const details = await provider.interactionDetails(req, res)

  console.log(details)

  if (details.prompt.name === 'login') {
    return res.render('login', {
      uid: req.params.uid,
      details: details.prompt.details,
      params: details.params,
      title: 'Sign-in',
      flash: undefined,
    })
  } else if (details.prompt.name === 'consent') {
    return res.render('consent', {
      uid: req.params.uid,
      details: details.prompt.details,
      params: details.params,
      title: 'Authorize',
    })
  }

  res.send(details)
})

app.post('/interactions/:uid/login', async (req, res) => {
  const details = await provider.interactionDetails(req, res)

  console.log(details)

  if (details.prompt.name === 'login') {
    let result
    console.log(req.body)
    if (req.body.username === 'kien' && req.body.password === 'kien') {
      result = {login: {accountId: 'kien'}}
    }

    return provider.interactionFinished(req, res, result, {mergeWithLastSubmission: false})
  }
})

app.post('/interactions/:uid/confirm', async (req, res) => {
  const details = await provider.interactionDetails(req, res)

  console.log(details)

  const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({
    accountId: details.session.accountId,
    clientId: details.params.client_id
  })


  if (grant) {
    if (details.prompt.details.missingOIDCScope) {
      grant.addOIDCScope(details.prompt.details.missingOIDCScope.join(' '))
    }
    if (details.prompt.details.missingResourceScopes) {
      console.log(details.prompt.details.missingResourceScopes)
      // key is resource, value is array of scopes
      for (const [resource, scopes] of Object.entries(details.prompt.details.missingResourceScopes)) {
        grant.addResourceScope(resource, scopes.join(' '))
      }
      // grant.addOIDCScope(details.prompt.details.missingOIDCScope.join(' '))
    }
    if (details.prompt.details.missingOIDCClaims) {
      grant.addOIDCClaims(details.prompt.details.missingOIDCClaims)
    }
    const grantId = await grant.save()

    const result = {consent: {grantId}}

    return provider.interactionFinished(req, res, result, {mergeWithLastSubmission: true})
  }
})

app.use('/oidc', provider.callback())

app.use((err, req, res, next) => {
  if (err)
  console.log(err)
  next()
})

app.listen(3000, () => {
  console.log('Server is up on port 3000')
})

provider.Session
