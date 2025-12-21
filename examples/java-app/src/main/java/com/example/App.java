package com.example;

import org.apache.commons.lang3.StringUtils;
import com.google.common.collect.ImmutableList;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashMap;
import java.util.Map;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) {
        while (true) {
            try {
                // 1. Commons Lang usage
                System.out.println(StringUtils.upperCase("Hello World from Java!"));

                // 2. Guava usage
                ImmutableList<String> list = ImmutableList.of("Item 1", "Item 2", "Item 3");
                System.out.println("Guava List: " + list);

                // 3. Jackson usage
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> data = new HashMap<>();
                    data.put("message", "Hello JSON");
                    data.put("items", list);
                    String json = mapper.writeValueAsString(data);
                    System.out.println("Jackson JSON: " + json);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                // 4. SLF4J usage
                logger.info("Application running...");

                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
