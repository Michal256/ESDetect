const express = require('express');
const _ = require('lodash');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
const chalk = require('chalk');

const app = express();
const port = 3000;

app.get('/', (req, res) => {
    console.log(chalk.green('Root endpoint called'));
    res.send('Hello from Node.js App!');
});

app.get('/math', (req, res) => {
    console.log(chalk.blue('Math endpoint called'));
    const numbers = [1, 2, 3, 4, 5];
    const sum = _.sum(numbers);
    const shuffled = _.shuffle(numbers);
    res.json({
        original: numbers,
        sum: sum,
        shuffled: shuffled
    });
});

app.get('/time', (req, res) => {
    console.log(chalk.yellow('Time endpoint called'));
    const now = moment();
    res.json({
        iso: now.toISOString(),
        human: now.format('MMMM Do YYYY, h:mm:ss a'),
        day: now.format('dddd')
    });
});

app.get('/id', (req, res) => {
    console.log(chalk.magenta('ID endpoint called'));
    res.json({
        id: uuidv4(),
        type: 'uuid-v4'
    });
});

app.listen(port, () => {
    console.log(chalk.cyan(`Server running on port ${port}`));
});
