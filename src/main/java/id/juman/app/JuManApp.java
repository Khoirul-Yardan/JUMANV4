
package id.juman.app;

import id.juman.core.AuthManager;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class JuManApp extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        // initialize data dirs and auth
        AuthManager.getInstance().init();
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/login.fxml"));
        Scene scene = new Scene(loader.load(), 760, 500);
        scene.getStylesheets().add(getClass().getResource("/styles/dark.css").toExternalForm());
        stage.setTitle("JuMan - JustManage");
        stage.setScene(scene);
        stage.setResizable(false);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
