const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required!'],
    trim: true,
    unique: [true, "This email is already in use!"],
    minLength: [5, "Email must be at least 5 characters long!"],
    lowercase: true,
  },
  password: {
    type: String,
    required: [true, "Provide Password!"],
    trim: true,
    select: false,
  },
  verified: {
    type: Boolean,
    default: false,
  },

  // ← Add this field
  verificationCode: {
    type: String,
    select: false,
  },

  // You already have this—just keep the name consistent
  verificationCodeValidation: {
    type: Number,
    select: false,
  },

  // (You can keep your other forgot-password fields as-is:)
  forgotPasswordCode: {
    type: String,
    select: false,
  },
  forgotPasswordCodeValidation: {
    type: Number,
    select: false,
  }
}, {
  timestamps: true
});

module.exports = mongoose.model("User", userSchema);
