<?php
require __DIR__ . '/vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use GuzzleHttp\Client;
use Carbon\Carbon;
use Symfony\Component\Console\Output\ConsoleOutput;

while (true) {
    // 1. Monolog
    $log = new Logger('name');
    $log->pushHandler(new StreamHandler('php://stdout', Logger::WARNING));
    $log->warning('Hello World from PHP!');

    // 2. Carbon
    printf("Current time (Carbon): %s\n", Carbon::now()->toDateTimeString());

    // 3. Symfony Console
    $output = new ConsoleOutput();
    $output->writeln('Symfony Console Output: Hello!');

    sleep(5);
}

