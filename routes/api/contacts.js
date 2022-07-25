const express = require("express");
const Joi = require("joi");

require("dotenv").config();

const Contact = require("../../models/contact");

const {authorize} = require('../../middlewares');
const { createError } = require("../../helpers");

const router = express.Router();

const contactSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().required(),
  phone: Joi.string().required(),
  favorite: Joi.boolean(),
});

const contactUpdateFavoriteSchema = Joi.object({
  favorite: Joi.boolean().required(),
});

router.get("/", authorize, async (req, res, next) => {
  try {
    const {_id: owner} = req.user;
    const result = await Contact.find({owner}, "-createdAt -updatedAt")
    // возьми id из owner, пойди в коллекцию которая записана в ref и найди информацию
    .populate('owner', "email, subscription");
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
});

router.get("/:id", authorize, async (req, res, next) => {
  try {
    const result = await Contact.findById(req.params.id);
    console.log(res);
    if (!result) {
      throw createError(404, "Not found");
    }

    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
});

router.post("/", authorize, async (req, res, next) => {
  try {
    const { error } = contactSchema.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }

    const result = await Contact.create({...req.body, owner: req.user._id});

    res.status(201).json(result);
  } catch (error) {
    next(error);
  }
});

router.delete("/:id", async (req, res, next) => {
  try {
    const result = await Contact.findByIdAndRemove(req.params.id);
    if (!result) {
      throw createError(404, "Contact not found");
    }
    res.status(204);
  } catch (error) {
    next(error);
  }
});

router.put("/:id", async (req, res, next) => {
  try {
    const { error } = contactSchema.validate(req.body);
    if (error) {
      throw createError(400, "missing fields");
    }
    const result = await Contact.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });

    if (!result) {
      throw createError(404, "Not found");
    }

    res.json(result);
  } catch (error) {
    next(error);
  }
});

router.patch("/:id/favorite", async (req, res, next) => {
  try {
    const { error } = contactUpdateFavoriteSchema.validate(req.body);
    if (error) {
      throw createError(400, "missing fields");
    }
    const result = await Contact.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });

    if (!result) {
      throw createError(404, "Not found");
    }

    res.json(result);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
