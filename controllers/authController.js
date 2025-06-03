const { exist } = require("joi");
const transport = require("../midllewares/sendMail");
const { signupSchema, signinSchema, acceptCodeSchema } = require("../midllewares/validator");
const User = require("../models/usersModel");
const {doHash, doHashValidation, hmacProcess} = require("../utils/hashing");
const jwt = require('jsonwebtoken');

exports.signup = async(req, res)=>{
    const{email, password} = req.body;
    try {
        const{error, value} = signupSchema.validate({email, password});



        if(error){
            return res.status(401).json({success:false, message:error.details[0].message})
        }

        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.status(401).json({success:false, message: "User already exists!"})
        }

        const hashedPassword = await doHash(password, 12);

        const newUser = new User({
            email, 
            password:hashedPassword,
        })
        const result = await newUser.save();
        result.password = undefined;
        res.status(201).json({
            success:true, message:"Your account has been created successfully!", 
            result,
        });
    }catch (error){
        console.log(error)
    }
};

exports.signin = async (req, res)=>{
    const {email, password} = req.body;
    
    try {
             const{error, value} = signinSchema.validate({email, password});
             if (error) {
                return res.status(401).json({success:false, message: error.details[0].message});
             }

             const existingUser = await User.findOne({email}).select('+password')
             if(!existingUser){
                return res.status(401).json({success:false, message:'User does not exist!'});
             }

             const result = await  doHashValidation(password, existingUser.password)
             if(!result){
                return res.status(401).json({success:false, message:'Invalid Credentials!'});
             }

             const token = jwt.sign({
                userId: existingUser._id,
                email: existingUser.email,
                verified: existingUser.verified,
             }, process.env.TOKEN_SECRET, 
             {
                expiresIn: '8h',
             }
            );


             res.cookie('Authorization', 'Bearer' +token, {expires: new Date(Date.now()+8*36000000), httoOnly:process.env.NODE_ENV === 'production', secure: process.env.NODE_ENV === 'production'})
             .json({
                sucess: true, 
                token, 
                message: 'You are logged in successfully',
             })
    } catch (error){

        console.log(error);
    }
};

exports.signout = async (req, res)=>{
    res
    .clearCookie('Authorization')
    .status(200)
    .json({success:true, message: 'logged out successfully'});

};

exports.sendVerificationCode = async (req, res) => {
    const { email } = req.body;

    try {
        const existingUser = await User.findOne({ email });

        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        if (existingUser.verified) {
            return res.status(400).json({ success: false, message: "You are already verified" });
        }

        const codeValue = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');

        let info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADRESS,
            to: existingUser.email,
            subject: "Verification Code",
            html: `<h1>${codeValue}</h1>`
        });

        if (info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now();
            await existingUser.save();

            return res.status(200).json({ success: true, message: "Code sent!" });
        }

        return res.status(400).json({ success: false, message: "Code sending failed!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};


exports.verifyVerificationCode = async (req, res) => {
    const { email, providedCode } = req.body;

    try {
        const { error } = acceptCodeSchema.validate({ email, providedCode });

        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }

        const codeValue = providedCode.toString();

        const existingUser = await User.findOne({ email }).select('+verificationCode +verificationCodeValidation');

        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        if (existingUser.verified) {
            return res.status(400).json({ success: false, message: "You are already verified" });
        }

        if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
            return res.status(400).json({ success: false, message: "Something is wrong with the code!" });
        }

        const isExpired = Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000;
        if (isExpired) {
            return res.status(400).json({ success: false, message: "The code has expired" });
        }

        const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

        if (hashedCodeValue === existingUser.verificationCode) {
            existingUser.verified = true;
            existingUser.verificationCode = undefined;
            existingUser.verificationCodeValidation = undefined;
            await existingUser.save();

            return res.status(200).json({ success: true, message: "Your account has been verified!" });
        }

        return res.status(400).json({ success: false, message: "Invalid verification code" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};
