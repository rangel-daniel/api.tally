import express from 'express';

const root = express.Router();

const wildcard = express.Router();

root.get('/', (_, res) => {
	return res.json({ message: 'Tally API' });
});

wildcard.all('*', (_, res) => {
	return res.status(404).json({ message: '404 - not found' });
});

export { root, wildcard };
