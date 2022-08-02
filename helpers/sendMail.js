const sgMail = require("@sendgrid/mail");
require("dotenv").config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendMail = async (data) => {
  try {
    const mail = { ...data, from: "tagirovantn@gmail.com" };
    await sgMail.send(mail);
    return true;
  } catch (error) {
    console.log(error.message);
  }
};

module.exports = sendMail ;