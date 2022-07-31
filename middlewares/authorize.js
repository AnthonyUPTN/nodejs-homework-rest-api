const jwt = require("jsonwebtoken");

const User = require("../models/user");

const  {createError}  = require("../helpers");
const { SECRET_KEY } = process.env;

const authorize = async (req, res, next) => {
  try {
    // забираем токен с заголовков запроса
    const { authorization = "" } = req.headers;
    const [ bearer, token ] = authorization.split(" ");
    if (bearer !== "Bearer") {
      throw createError(401, "Not authorized");
    }
    try {
      // проверяем зашифрован ли этот токен нашим ключём
      const { id } = jwt.verify(token, SECRET_KEY);

      const user = await User.findById(id);
      if(!user || !user.token){
        throw createError(401, "Not authorized");
      }
      // записываем в req(глобально) информацию о том пользователе который делает запрос
      req.user = user;
      next();
    } catch (error) {
        throw createError(401, "Not authorized");
    }
  } catch (error) {
    next(error);
  }
};

module.exports = authorize;
