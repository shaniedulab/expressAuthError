const { error } = require('console');
const userModel=require('./../Models/userModel');
const CustomError=require('./../Utils/CustomError');
const jwtToken= require('./../Utils/jwtToken');
const jwt=require('jsonwebtoken');
const util = require('util');
const sendEmail=require('./../Utils/email');
const crypto=require('crypto');
const { Op } = require("sequelize");

class userController{
    static async signup(req,res,next){
        const newUser=await userModel.create(req.body);

        const token= jwtToken(newUser.id)

        res.status(201).json({
            status:'success',
            token,
            data:newUser
        })
    }

    static async login(req,res,next){
        const email=req.body.email;
        const password=req.body.password;
        console.log(email,password);
        // const {email,password}=req.body;
        //check email & password is present in request body.
        if(!email || !password){
            const error=new CustomError('Please provide email Id & password for login in!',400)
            return next(error);
        }

        //check if user exits with given email.
        const user=await userModel.findOne({where:{email}});

        // const isMatch=await userModel.comparePasswordInDb(password,user.password);

        //check user exit and password matchs.
        if(!user || !(await userModel.comparePasswordInDb(password,user.password))){
            console.log("user",await userModel.comparePasswordInDb(password,user.password))
            const error=new CustomError('Incorrect email or Password',400);
            return next(error);
        }

        const token= jwtToken(user.id)

        res.json({
            status:'success',
            token
        })
    }

    static async protect(req,res,next){
        //1. read the token & check if it exits
        const testToken=req.headers.authorization;
        // console.log(req.headers);
        // console.log();
        let token;
        if(testToken && testToken.startsWith("Bearer")){
            token=testToken.split(' ')[1];
        }
        // console.log(token);
        if(!token){
            return next(new CustomError('You are not logged in!',401));
        }
        //2. validate the token 
        const decodedtoken=await util.promisify(jwt.verify)(token,process.env.SECRET_STR);
        // console.log("de",decodedtoken);

        //3. if the usre exits 
        const user=await userModel.findOne({where:{id:decodedtoken.id}});
        // console.log("useruser",user);
        if(!user){
            const err=new CustomError('The user with given Token does not exist',401);
            return next(err);
        }
        //4. if the user changed password ofter the token was issued

        const beforChangedPassword=await userModel.isPasswordChaned(decodedtoken.iat,user.passwordChanedAt);
        if(beforChangedPassword){
            const err = new CustomError('The password has been changed recently. Please login again',401);
            return next(err)
        }
        //5.allow user to access route.
        req.user=user;

        next();
    }

    //allow user to access route. add multiple role to uae ... operater and includs methos
    static restrict(role){
        return (req,res,next)=>{
            if(req.user.role!==role){
                const err=new CustomError('You do not have permission to perform this action',403)
                next(err);
            }
            next();
        }
    }

    //password reset functionality
    static async forgotPassword(req,res,next){
        //1. get user bsed on posted email
        const user=await userModel.findOne({where:{email:req.body.email}})
        if(!user){
            const err=new CustomError('We could not find the user with given email',404)
            next(err);
        }

        //2. generate a random reset token
        const {resetToken,passwordResetToken,passwordResetTokenExpires}=await userModel.createResetPasswordToken();
        const user1=await user.update({
            passwordResetToken:passwordResetToken,
            passwordResetTokenExpires:passwordResetTokenExpires
        });

        //3.send the token back to the user email
        const resetUrl=`${req.protocol}://${req.get('host')}/user/resetPassowrd/${resetToken}`;
        const message=`We have reseverd a password reset request. Please use the below link to reset your password\n\n${resetUrl}\n\nThis reset password link will be valid for 10 minutes`
        try{
            await sendEmail({
                email:user.email,
                subject:'Password change request received',
                message:message,
            });

            res.status(200).json({
                status:'sucess',
                message:'password reset link send to the user email',
            })
        }catch(error){
            await user.update({
                passwordResetToken:undefined,
                passwordResetTokenExpires:undefined
            });
            next(new CustomError('There was an error sending password reset email. Please try again later',500));
        }
    }

    static async resetPassowrd(req,res,next){
        //1. if the user exits with the given token &token has not expired.
        const token= crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user= await userModel.findOne({where:{passwordResetToken:token,passwordResetTokenExpires:{[Op.gt]:Date.now()}}})
        // console.log("useresr",user);
        if(!user){
            const err=new CustomError('Token is invalid or has expires!',400);
            next(err);
        }
        //2.reseting the user Password
        await user.update({
            password:req.body.password,
            passwordChanedAt:Date.now(),
            confirmpassword:req.body.confirmpassword,
            passwordResetToken:null,
            passwordResetTokenExpires:null
        });

        //3. login the user
        const logintoken= jwtToken(user.id)

        res.json({
            status:'success',
            token:logintoken
        })
    }
}


module.exports=userController;