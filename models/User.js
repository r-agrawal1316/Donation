const mongoose = require('mongoose');
const { hashPassword } = require('./hash');

const registrationschema = new mongoose.Schema({
    Name: {
        type: String,
    },
    Username: {
        type: String,
        required: true,
        unique: true,
    },
    Email: {
        type: String,
        required: true,
        unique: true,
    },
    Password: {
        type: String,
    },
    isAdmin: {
        type: Boolean,
        default: false,
    },
    registrationDate: {
        type: Date,
        default: Date.now,
    },
    resetToken: String,
    resetTokenExpiration: Date,
    otp: String,
    otpExpiration: Date,
    isVerified: Boolean,
});

registrationschema.pre('validate', async function (next) {
    const user = this;
    try {
        if (user.isModified('Password')) {
            const hashedPassword = await hashPassword(user.Password);
            user.Password = hashedPassword;
        }
        next();
    } catch (err) {
        next(err);
    }
});

const registration = mongoose.model('Registration', registrationschema);

module.exports = registration;
