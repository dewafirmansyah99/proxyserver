const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');

const COLLECTION = 'movies';

// @route   GET api/items
// @desc    Get All Items
// @access  Public
router.get('/', async (req, res) => {
    try {
        const db = req.app.locals.db;
        const items = await db.collection(COLLECTION)
            .find({})
            .sort({ createdAt: -1 })
            .toArray();

        res.json(items);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});