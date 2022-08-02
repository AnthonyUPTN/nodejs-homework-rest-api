const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
require("dotenv").config();
const path = require("path");
const fs = require("fs/promises");
const Jimp = require("jimp");
const { nanoid } = require("nanoid");

const { createError, sendMail } = require("../../helpers");
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

const verifyEmailSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
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

    const verificationToken = nanoid();

    const result = await User.create({
      email,
      password: hashPassword,
      avatarURL,
      verificationToken,
    });

    const mail = {
      to: email,
      subject: "Verify email",
      html: `<a target="_blank" href="http://localhost:3000/api/auth/verify/${verificationToken}">Click to verify your email</a>`,
    };
    await sendMail(mail);

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
    const passwordCompare = await bcrypt.compare(password, user?.password);

    if (!user || !passwordCompare) {
      throw createError(401, "Email or password is wrong");
    }

    if (!user.verify) {
      throw createError(401, "Email wrong");
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
        }
        image.resize(250, 250).write(uploadDir);
      });
      const avatarURL = path.join("avatars", newAvatar);
      // обновляем данные пользователя дописывая путь к аватарке

      await User.findByIdAndUpdate(req.user._id, { avatarURL });
      res.json({
        avatarURL,
      });
    } catch (error) {
      await fs.unlink(req.file.path);
      next(error);
    }
  }
);

router.post("/verify", async (req, res, next) => {
  try {
    const { error } = verifyEmailSchema.validate(req.body);

    if (error) {
      throw error;
    }
    
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      throw createError(404, "User not found");
    }

    if (user.verify) {
      throw createError(400, "Verification has already been passed");
    }

    const mail = {
      to: email,
      subject: "Verify email",
      html: `<a target="_blank" href="http://localhost:3000/api/auth/verify/${user.verificationToken}">Click to verify yout email</a>`,
    };

    await sendMail(mail);
    res.status(400).json({
      message: "Verification has already been passed",
    });
  } catch (error) {
    next(error);
  }
});

router.get("/verify/:verificationToken", async (req, res, next) => {
  try {
    const { verificationToken } = req.params;
    const user = await User.findOne({ verificationToken });

    if (!user) {
      throw createError(404, "User not found");
    }

    await User.findByIdAndUpdate(user._id, {
      verificationToken: "",
      verify: true,
    });

    res.status(200).json({
      message: "Verification successfull",
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
