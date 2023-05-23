const { parse } = require('yamljs');
// const userController = require('../Controllers/userController');
const {sequelize,DataTypes} = require('../sequelize')
const bcryptjs=require('bcryptjs')
const crypto=require('crypto');
// const { STRING } = require('sequelize');

const user = sequelize.define('Users', {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      // unique: true
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
        notNull: {
          msg: 'Please enter your email'
        },
      },
      set(val) {
        this.setDataValue('email', val.toLowerCase());
      }
    },
    photo:{
      type:DataTypes.STRING,
    },
    role:{
      type: DataTypes.ENUM("user", "admin"),
      defaultValue:'user'
    },
    password:{
      type: DataTypes.STRING,
      allowNull: false,
      validate:{
        isMinLength(value) {
          if (value.length<8) {
            throw new Error('Minimun 8 character allow');
          }
        } 
      } 
    },
    confirmpassword:{
      type: DataTypes.STRING,
      allowNull: false,
      validate:{
        isMatchPassword(value){
          if(value != this.password){
            throw new Error('Password & Confirm Password does not match!');
          }
        }
      }
    },
    passwordChanedAt:{
      type: DataTypes.DATE,
    },
    passwordResetToken:{
      type:DataTypes.STRING,
    },
    passwordResetTokenExpires:{
      type:DataTypes.DATE
    }
  }, {
    // Other model options go here
  });

  //hash password before hash password //hooks
  user.beforeCreate(async (user, options) => {
    const hashedPassword = await bcryptjs.hash(user.password,12);
    user.password = hashedPassword;
    user.confirmpassword = hashedPassword;
  });

  user.beforeUpdate(async (user, options) => {
    const hashedPassword = await bcryptjs.hash(user.password,12);
    user.password = hashedPassword;
    user.confirmpassword = hashedPassword;
  });
  
  //comparing password 
  user.comparePasswordInDb= async function(pass,passDb){
    return await bcryptjs.compare(pass,passDb);
  }

  user.isPasswordChaned= async function(jwtTime,changTime){
    const pswdChangedTimestemp=parseInt(changTime.getTime()/1000,10);
    // console.log(jwtTime<pswdChangedTimestemp);
    if(jwtTime<pswdChangedTimestemp){
      return true;
    }
    return false;
  }

  user.createResetPasswordToken= async function(){
    // console.log("sdfsd");
    const resetToken=crypto.randomBytes(32).toString('hex');
    // console.log("kk",resetToken);
    const passwordResetToken=crypto.createHash('sha256').update(resetToken).digest('hex');
    const passwordResetTokenExpires=Date.now()+(10*60*1000)

    return {resetToken,passwordResetToken,passwordResetTokenExpires};
  }

module.exports= user
