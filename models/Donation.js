const mongoose = require('mongoose');

const donatemoneyschema = new mongoose.Schema({
    Name: String,
    Phone: Number,
    Amount: Number,
    Purpose: String,
    Moneydonatedate: {
        type: Date,
    }
})

const Donation = mongoose.model('moneydonors', donatemoneyschema);

module.exports = Donation;