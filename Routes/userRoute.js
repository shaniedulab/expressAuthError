const router = require('express').Router();
const userController=require('./../Controllers/userController')
const asyncErrorHandler= require('./../Utils/asyncErrorHandler')

router.route('/signup').post(asyncErrorHandler(userController.signup));
router.route('/login').post(asyncErrorHandler(userController.login));
router.route('/forgotPassword').post(asyncErrorHandler(userController.forgotPassword));
router.route('/resetPassword/:token').patch(asyncErrorHandler(userController.resetPassowrd));

module.exports=router;