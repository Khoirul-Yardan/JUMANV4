
package id.juman.ui;

import id.juman.core.AuthManager;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.util.Optional;

public class LoginController {
    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private Label statusLabel;
    @FXML private Button loginBtn;
    @FXML private Hyperlink forgotLink;

    @FXML
    public void initialize(){
        usernameField.setText("admin");
        statusLabel.setText("Login with admin / 123 (demo). On first run, master key & recovery generated.");
    }

    @FXML
    public void onLogin(ActionEvent ev){
        String u = usernameField.getText().trim();
        String p = passwordField.getText();
        try {
            AuthManager am = AuthManager.getInstance();
            if (!u.equals("admin")) { statusLabel.setText("Unknown user"); return; }
            if (am.verifyPassword(p)) {
                Stage stage = (Stage) loginBtn.getScene().getWindow();
                javafx.fxml.FXMLLoader loader = new javafx.fxml.FXMLLoader(getClass().getResource("/fxml/main.fxml"));
                stage.getScene().setRoot(loader.load());
            } else {
                statusLabel.setText("Invalid credentials.");
            }
        } catch (Exception e){
            statusLabel.setText("Failed to open main UI: " + e.getMessage());
        }
    }

    @FXML
    public void onForgot(ActionEvent ev){
        try {
            TextInputDialog tid = new TextInputDialog();
            tid.setTitle("Recover account");
            tid.setHeaderText("Enter your recovery key");
            tid.setContentText("Recovery key:");
            Optional<String> res = tid.showAndWait();
            if (res.isPresent()){
                String token = res.get().trim();
                if (AuthManager.getInstance().verifyRecoveryToken(token)){
                    // prompt for new password
                    Dialog<String> dlg = new Dialog<>();
                    dlg.setTitle("Set new password");
                    dlg.setHeaderText("Enter a new password for the admin account");
                    ButtonType ok = new ButtonType("Set", ButtonBar.ButtonData.OK_DONE);
                    dlg.getDialogPane().getButtonTypes().addAll(ok, ButtonType.CANCEL);
                    PasswordField pf1 = new PasswordField();
                    pf1.setPromptText("New password");
                    PasswordField pf2 = new PasswordField();
                    pf2.setPromptText("Confirm password");
                    VBox vb = new VBox(8, new Label("New password:"), pf1, new Label("Confirm:"), pf2);
                    dlg.getDialogPane().setContent(vb);
                    dlg.setResultConverter(bt -> {
                        if (bt == ok) return pf1.getText();
                        return null;
                    });
                    Optional<String> pnew = dlg.showAndWait();
                    if (pnew.isPresent()){
                        String np = pnew.get();
                        if (!np.equals(pf2.getText())) { statusLabel.setText("Passwords do not match"); return; }
                        AuthManager.getInstance().resetPasswordWithRecovery(token, np);
                        statusLabel.setText("Password reset. You can now login with the new password.");
                    }
                } else {
                    statusLabel.setText("Invalid recovery key.");
                }
            }
        } catch (Exception e){ statusLabel.setText("Recovery failed: " + e.getMessage()); }
    }
}
