const mongoose = require('mongoose');

const fallAlertSchema = new mongoose.Schema({
    type: { type: String, default: 'fall' },
    location: { type: String, default: 'unknown' },
    timestamp: { type: Date, default: Date.now },
    acknowledged: { type: Boolean, default: false }
});

module.exports = mongoose.model('FallAlert', fallAlertSchema);