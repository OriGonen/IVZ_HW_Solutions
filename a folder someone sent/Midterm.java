package isp.kolokvij;

import fri.isp.Agent;
import fri.isp.Environment;

public class Midterm {
    public static void main(String[] args) throws Exception {

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {}
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {}
        });

        env.connect("alice", "bob");
        env.start();
    }
}
