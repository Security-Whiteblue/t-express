/**
 *
 * The copyright indication and this authorization indication shall be
 * recorded in all copies or in important parts of the Software.
 *
 * @author dev-ys-36, earlgrey02
 * @link https://github.com/dev-ys-36, https://github.com/earlgrey02
 * @license MIT LICENSE
 *
 */

import express from 'express'
import expressSession from 'express-session'
import { body, validationResult } from 'express-validator'
import bodyParser from 'body-parser'
import mysql from 'mysql'
import http from 'http'

const app = express()

const pool = mysql.createPool({
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'wb-proj',
  database: 'proj',
  dateStrings: 'date',
})

const checkEmail = (content) => {
  const email = /^([0-9a-zA-Z_\.-]+)@([0-9a-zA-Z_-]+)(\.[0-9a-zA-Z_-]+){1,2}$/
  return !email.test(content) ? true : false
}

app.use(
  expressSession({
    secret: 'wb-proj',
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 1, // 1 hours
    },
  }),
)

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.post(
  '/auth/register',
  body('userid').exists(),
  body('password').exists(),
  body('email').exists(),
  async (req, res) => {
    const errorFormatter = ({ location, msg, param, value, nestedErrors }) => {
      return param + ': ' + msg
    }
    const result = validationResult(req).formatWith(errorFormatter)

    if (!result.isEmpty()) {
      res.status(401).send(result)
      return
    }

    const { userid, password, email } = req.body

    if (!checkEmail(email)) {
      res.status(401).send({ statusCode: 401, message: 'email error.' })
      return
    }

    pool.getConnection((error, connection) => {
      if (error) throw error

      connection.query(
        'SELECT * FROM user WHERE userid = ? AND password = ? AND email = ?',
        [userid, password, email],
        (error, results) => {
          if (error) throw error

          if (results.length > 0) {
            res.status(401).send({ statusCode: 401, message: 'already account.' })
            return
          }

          connection.query(
            'INSERT INTO user (userid, password, email) VALUES (?, ?, ?)',
            [userid, password, email],
            (error, result) => {
              if (error) throw error

              connection.release()
            },
          )

          res.status(200).send({ statusCode: 200, message: 'success register.' })
        },
      )
    })
  },
)

app.post('/auth/login', body('userid').exists(), body('password').exists(), async (req, res) => {
  const errorFormatter = ({ location, msg, param, value, nestedErrors }) => {
    return param + ': ' + msg
  }
  const result = validationResult(req).formatWith(errorFormatter)

  if (!result.isEmpty()) {
    res.status(401).send(result)
    return
  }

  const { userid, password } = req.body

  pool.getConnection((error, connection) => {
    if (error) throw error

    connection.query(
      'SELECT * FROM user WHERE userid = ? AND password = ?',
      [userid, password],
      (error, results) => {
        if (error) throw error

        connection.release()

        if (results.length <= 0) {
          res.status(401).send({ statusCode: 401, message: 'unregistered.' })
          return
        }

        req.session.user = {
          id: results[0].id,
          userid: results[0].username,
          password: results[0].password,
          email: results[0].email,
        }

        res.status(200).send({ statusCode: 200, message: 'success login.' })
      },
    )
  })
})

app.get('/auth/logout', async (req, res) => {
  if (req.session.user === undefined) {
    res.status(401).send({ statusCode: 401, message: 'unlogined.' })
    return
  }

  req.session.destroy((error) => {
    if (error) throw error
  })
  res.status(200).send({ statusCode: 200, message: 'success logout.' })
})

app.get('*', (req, res) => {
  res.status(401).send({ statusCode: 401, message: 'unknown request.' })
})

http.createServer(app).listen(1010, '0.0.0.0')
