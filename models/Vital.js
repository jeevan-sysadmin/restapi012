const mongoose = require('mongoose');

const vitalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    heartRate: { type: Number, required: true },
    movement: { type: String, required: true },
    status: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Vital', vitalSchema);