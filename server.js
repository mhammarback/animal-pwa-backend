import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'


const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/animal"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.Promise = Promise

const port = process.env.PORT || 8080
const app = express()

app.use(cors())
app.use(bodyParser.json())

const userSchema = new mongoose.Schema({
  name: {
    type: String, 
    minlength: 2, 
    maxlength: 20,
    required: true, 
    unique: true,
  },
  password: {
    type: String, 
    minlength: 5, 
    maxlength: 20,
    required: true,
  }, 
  accessToken: {
    type: String, 
    default: () => crypto.randomBytes(128).toString('hex')
  }
})

userSchema.pre('save', async function (next) {
  const user = this
  if (!user.isModified('password')) {
    return next()
  }
  const salt = bcrypt.genSaltSync(10)
  user.password = bcrypt.hashSync(user.password, salt)
  next()
})

// Models 

const User = mongoose.model('User, userSchema')

const AnimalProfile = mongoose.model('AnimalProfile', {
  userId: {
    type: String, 
    required: true,
  },
  animalName: {
    type: String, 
    required: true, 
    minlength: 2, 
    maxlength: 20, 
  }, 
  createdAt: {
    type: Date, 
    default: Date.now,
  },
  birthDate: {
    type: Number, 
    required: true,
  },
  gender: {
    type: String, 
    required: true,
  }, 
  weight: {
    type: Number, 
  },
  breed: {
    type: String,
    required: true,
  },
})


//Authentication 
const authenticateUser = async (req, res, next) => {
  try {
    const user = await User.findOne({ accessToken: req.header('Authorization')})

    if (user) {
      req.user = user
      next()
    } else {
      res.status(401).json({ loggedOut: true, message: 'Please try logging in again'})
    }
  } catch (err) {
    res.status(403).json({ message: 'Access token missing or wrong', errors:err})
  }
}


app.get('/', (req, res) => {
  res.send(listEndpoints(app))
})

//Sign up 
app.post('./users', async (req,res) => {
  try {
    const { name, password } = req.body
    const user = await new User({ name, password }).save()
    res.status(201).json({ accessToken: user.accessToken })
  } catch (error) {
    res.status(400).json({ message: 'could not create user', error})
  }
})

//Login
app.post('./sessions', async (req, res) => {
  try {
    const { name, password } = req.body
    const user = await User.findOne({ name })

    if(user && bcrypt.compareSync(password, user.password)) {
      res.status(201).json({ accessToken: user.accessToken })
    } else {
      res.status(404).json({ notFound: true, message: 'Verify username and password'})
    }
  } catch (err) {
    res.status(500).json({notFound: true, message: 'Internal Server Error'})
  }
})

//POST Restricted enpoint, Animalprofile
app.post('./profiles', authenticateUser)
app.post('./profiles', async (res,res) => {
  const userId = req.user.id
  const { animalName, birthDate, gender, weight, breed } = req.body

  const animalProfile = new AnimalProfile({ userId, animalName, birthDate, gender, weight, breed })

  try {
    const savedAnimalProfile = await animalProfile.save()
    res.status(200).json({message: 'Animal profile saved successfully' })
  } catch (error) {
    res.status(400).json({ message: 'Could not save Animal profile', error})
  }
}) 

//GET Restricted endpoint
app.get('./profiles', authenticateUser)
app.get('./profiles', async (res,req) => {
  const userId = req.user.id

  try {
    const profile = await AnimalProfile.findOne({ userId })
    res.json(profile)
  } catch (err) {
    res.status(500).json(err)
  }
})


app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
