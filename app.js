const express = require('express')
const cookieParser = require('cookie-parser')
const logger = require('morgan')
const AWS = require('aws-sdk')
const { v4: uuidv4 } = require('uuid')
const cors = require('cors')
const CognitoExpress = require('cognito-express')

const cognitoExpress = new CognitoExpress({
  region: 'us-east-2',
  cognitoUserPoolId: 'us-east-2_mgu0KIw6Z',
  tokenUse: 'access', // Possible Values: access | id
  tokenExpiration: 3600000 // Up to default expiration of 1 hour (3600000 ms)
})

const app = express()

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(cors())

AWS.config.loadFromPath('./config.json')
AWS.config.apiVersions = {
  dynamodb: 'latest'
}
const db = new AWS.DynamoDB.DocumentClient()

const requireAuth = (req, res, next) => {
  const accessTokenFromClient = req.headers['access-token']

  cognitoExpress.validate(accessTokenFromClient, function (err, response) {
    if (err) {
      return res.status(401).send(err)
    }
    res.locals.user = response
    next()
  })
}

const requireAdmin = (req, res, next) => {
  const groups = res.locals.user['cognito:groups']
  if (!groups || !groups.includes('admins')) {
    return res.status(401).send()
  }
  next()
}

app.get('/emails/processing', requireAuth, (req, res) => {
  const expiredTimestampRange = Date.now() - 120000 // 2 minutes ago
  const currentUser = res.locals.user.username

  db.scan({
    TableName: 'Emails',
    FilterExpression: '((lastProcessingBy = :currentUser AND lastAssignedAt > :expiredTimestampRange) OR (lastAssignedAt < :expiredTimestampRange OR attribute_not_exists(lastAssignedAt))) AND #status = :pending',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':expiredTimestampRange': expiredTimestampRange,
      ':pending': 'pending',
      ':currentUser': currentUser
    }
  }, function (err, data) {
    if (err) {
      throw err
    }
    const item = data.Items.sort((a, b) => a.date - b.date)[0]
    if (item) {
      let newLastAssignedAt = Date.now()
      if (item.lastProcessingBy === currentUser && item.lastAssignedAt > expiredTimestampRange) {
        newLastAssignedAt = item.lastAssignedAt
      }
      db.update({
        TableName: 'Emails',
        Key: {
          id: item.id
        },
        UpdateExpression: 'set lastAssignedAt = :now, lastProcessingBy = :currentUser',
        ExpressionAttributeValues: {
          ':now': newLastAssignedAt,
          ':currentUser': currentUser
        },
        ReturnValues: 'ALL_NEW'
      }, (err, item) => {
        if (err) {
          throw err
        }
        res.json(item.Attributes)
      })
    } else {
      res.json(null)
    }
  })
})

app.get('/emails/admin', requireAuth, requireAdmin, (req, res) => {
  db.scan({
    TableName: 'Emails'
  }, function (err, data) {
    if (err) {
      throw err
    }
    res.json(data.Items)
  })
})

app.post('/emails/:id/resolve', requireAuth, (req, res) => {
  const { status } = req.body
  const { id } = req.params
  const currentUser = res.locals.user.username
  const processedBy = status === 'pending' ? null : currentUser
  const processedAt = processedBy ? +Date.now() : null
  db.update({
    TableName: 'Emails',
    Key: {
      id: id
    },
    UpdateExpression: 'SET #status = :status, processedAt = :processedAt, processedBy = :processedBy REMOVE lastAssignedAt, lastProcessingBy',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':status': status,
      ':processedAt': processedAt,
      ':processedBy': processedBy
    },
    ReturnValues: 'ALL_NEW'
  }, (err, item) => {
    if (err) {
      throw err
    }
    if (status === 'positive' || status === 'neutral') {
      new AWS.SES({ apiVersion: '2010-12-01' }).sendEmail({
        Destination: {
          ToAddresses: [
            'alex+email.receiver@vessent.com'
          ]
        },
        Message: {
          Body: {
            Text: {
              Charset: 'UTF-8',
              Data: item.Attributes.body
            }
          },
          Subject: {
            Charset: 'UTF-8',
            Data: item.Attributes.subject
          }
        },
        Source: 'alex+email.sender@vessent.com'
      }).promise()
    }
    res.json({})
  })
})

app.post('/set-me-as-away', requireAuth, (req, res) => {
  const { emailId } = req.body
  db.update({
    TableName: 'Emails',
    Key: {
      id: emailId
    },
    UpdateExpression: 'REMOVE lastAssignedAt, lastProcessingBy'
  }, (err) => {
    if (err) {
      throw err
    }
    res.json({})
  })
})

app.put('/emails', (req, res) => {
  db.put({
    TableName: 'Emails',
    Item: {
      id: uuidv4(),
      address: req.body.Email_lead,
      body: req.body.Body,
      date: +new Date(req.body.Date),
      subject: req.body.Subject,
      status: 'pending'
    }
  }, function (err) {
    if (err) {
      return res.status(400).send(err)
    }
    res.json({})
  })
})

module.exports = app
