const mongoose = require('mongoose');

const dailyLogSchema = new mongoose.Schema({
    date: { type: Date, required: true },
    fallsDetected: { type: Number, default: 0 },
    vitalsRecorded: { type: Number, default: 0 },
    sosTriggered: { type: Number, default: 0 }
});

module.exports = mongoose.model('DailyLog', dailyLogSchema);