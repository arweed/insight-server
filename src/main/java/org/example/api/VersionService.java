package org.example.api;

import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import java.io.IOException;
import java.io.InputStream;
import java.util.jar.Manifest;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/version")
public class VersionService {

    @Inject
    private ServletContext context;

    @GET
    @Produces(APPLICATION_JSON)
    public String getVersion() throws IOException {
        InputStream inputStream = context.getResourceAsStream("/META-INF/MANIFEST.MF");
        Manifest manifest = new Manifest(inputStream);
        return manifest.getMainAttributes().getValue("version");
    }
}
