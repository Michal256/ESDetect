import ArgumentParser
import Foundation
import Logging
import Collections
import Algorithms

struct SwiftApp: ParsableCommand {
    func run() throws {
        while true {
            // 1. Logging
            let logger = Logger(label: "com.example.swiftapp")
            logger.info("Hello World from Swift!")

            // 2. Collections (Deque)
            var deque: Deque<String> = ["First", "Second"]
            deque.prepend("Zero")
            print("Deque: \(deque)")

            // 3. Algorithms
            let numbers = [10, 20, 30, 40]
            let chunks = numbers.chunks(ofCount: 2)
            for chunk in chunks {
                print("Chunk: \(chunk)")
            }

            Thread.sleep(forTimeInterval: 5.0)
        }
    }
}

SwiftApp.main()
