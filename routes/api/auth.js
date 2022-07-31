const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
require("dotenv").config();
const path = require("path");
const fs = require("fs/promises");
const Jimp = require("jimp");

const { createError } = require("../../helpers");
const { authorize, upload } = require("../../middlewares");

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

    // создаем рандомный аватар с помощью gravatar
    const avatarURL = gravatar.url(email);

    const result = await User.create({
      email,
      password: hashPassword,
      avatarURL,
    });

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
    await User.findByIdAndUpdate(user._id, { token });

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

router.get("/logout", authorize, async (req, res) => {
  const { _id } = req.user;
  const user = await User.findById(_id);
  if (!user) {
    throw createError(401, "Not authorized");
  }

  await User.findByIdAndUpdate(_id, { token: "" });
});

router.get("/current", async (req, res, next) => {
  const { email, subscription } = req.user;
  res.status(200).json({
    user: {
      email,
      subscription,
    },
  });
});

const avatarsDir = path.join(__dirname, "../../public", "avatars");

// через upload.single сохраняем файл в tmp
router.patch(
  "/avatars",
  authorize,
  upload.single("avatar"),
  async (req, res, next) => {
    try {
      const { path: dirName, originalname } = req.file;
      const [extention] = originalname.split(".").reverse();
      const newAvatar = path.join(`${req.user._id}.${extention}`);
      const uploadDir = path.join(avatarsDir, newAvatar);
      // перекидываем с tmp в public/avatars
      await fs.rename(dirName, uploadDir);
      Jimp.read(uploadDir, (error, image) => {
        if (error) {
          next(error);
        };
        image
          .resize(250, 250) 
          .write(uploadDir); 
      });
      const avatarURL = path.join("avatars", newAvatar);
      // обновляем данные пользователя дописывая путь к аватарке
    
      await User.findByIdAndUpdate(req.user._id,  {avatarURL} );
      res.json({
       avatarURL
      });
    } catch (error) {
      await fs.unlink(req.file.path);
      next(error);
    }
  }
);

module.exports = router;
