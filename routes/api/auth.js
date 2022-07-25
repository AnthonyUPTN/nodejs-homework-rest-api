const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const { createError } = require("../../helpers");
const {authorize} = require('../../middlewares');

const User = require("../../models/user");

const router = express.Router();

const { SECRET_KEY } = process.env;
const emailRegexp = /[a-z0-9]+@[a-z]+\.[a-z]{2,3}/;

const userRegisterSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().min(6).required(),
  subscription: Joi.string(),
});

router.post("/singup", async (req, res, next) => {
  try {
    // проверка через Joi
    const { error } = userRegisterSchema.validate(req.body);
    if (error) {
      throw createError(400, "Ошибка от Joi или другой библиотеки валидации");
    }
    // проверка есть ли такой пользователь в базе
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      throw createError(409, "Email in use");
    }
    // если нет такого пользователя создаём его
    const hashPassword = await bcrypt.hash(password, 10);

    const result = await User.create({ email, password: hashPassword });

    res.status(201).json({
      email: result.email,
      subscription: result.subscription,
    });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { error } = userRegisterSchema.validate(req.body);
    if (error) {
      throw createError(400, "Ошибка от Joi или другой библиотеки валидации");
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    const passwordCompare = await bcrypt.compare(password, user.password);

    if (!user || !passwordCompare) {
      throw createError(401, "Email or password is wrong");
    }
    // создаем токен
    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "24h" });
    // обновляем токен текущему пользователю
    await User.findByIdAndUpdate(user._id, {token});

    res.status(200).json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authorize, async (req, res, next) => {
  const {_id} = req.user;
  const user = await User.findById(_id);
  if(!user){
    throw createError(401, "Not authorized");
  }

  await User.findByIdAndUpdate(_id, {token: ''})
})

router.get('/current', async (req, res, next) => {
  const {email, subscription} = req.user;
  res.status(200).json({
    user: {
      email,
      subscription,
    },
  });
})

module.exports = router;
