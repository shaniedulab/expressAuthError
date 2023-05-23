const nodemailer= require('nodemailer');

const sendEmail = async (options) => {
    // console.log("email",options);
    //create a transpoter servece
    const transpoter=nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port:process.env.EMAIL_PORT,
        auth:{
            user:process.env.EMAIL_USER,
            pass:process.env.EMAIL_PASSWORD
        }
    })

    //define email options
    const emailOptions={
        from:'shani@gmail.com',
        to:options.email,
        subject:options.subject,
        text:options.message
    }

    await transpoter.sendMail(emailOptions)
}
module.exports = sendEmail;