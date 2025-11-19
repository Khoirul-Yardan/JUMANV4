
package id.juman.ui;

import id.juman.core.AuthManager;
import id.juman.core.BackupService;
import id.juman.core.FileManager;
import java.awt.Desktop;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainController {
    @FXML
    private Label infoLabel;
    @FXML
    private Label statusLabel;
    @FXML
    private ListView<String> listView;
    @FXML
    private Button addBtn, openBtn, exportBtn, backupBtn, refreshBtn, deleteBtn, recoverBtn;

    private FileManager fileManager;
    private BackupService backupService;
    private SecretKey masterKey;
    // map displayed name -> stored filename
    private Map<String, String> displayToStored = new HashMap<>();

    public void initialize() {
        try {
            Path data = AuthManager.getInstance().getDataDir();
            fileManager = new FileManager(data);
            backupService = new BackupService(data);
            masterKey = AuthManager.getInstance().getMasterKey();
            infoLabel.setText("Storage: " + data.toAbsolutePath().toString());
            refreshList();
        } catch (Exception e) {
            infoLabel.setText("Init error: " + e.getMessage());
        }
    }

    @FXML
    public void onAdd(ActionEvent ev) {
        FileChooser fc = new FileChooser();
        File f = fc.showOpenDialog(addBtn.getScene().getWindow());
        if (f != null) {
            try {
                String stored = fileManager.storeEncrypted(f, masterKey);
                infoLabel.setText("Stored: " + stored);
                refreshList();
            } catch (Exception e) {
                infoLabel.setText("Error: " + e.getMessage());
            }
        }
    }

    @FXML
    public void onOpen(ActionEvent ev) {
        String sel = listView.getSelectionModel().getSelectedItem();
        if (sel == null) {
            infoLabel.setText("Select a file first.");
            return;
        }
        String stored = displayToStored.get(sel);
        if (stored == null) {
            infoLabel.setText("Internal mapping missing.");
            return;
        }
        try {
            File tmp = fileManager.decryptToTemp(stored, masterKey);
            // determine original extension
            String orig = stored;
            int idx = stored.indexOf("__");
            if (idx >= 0)
                orig = stored.substring(idx + 2).replaceAll("\\.jmn$", "");
            String ext = "";
            int dot = orig.lastIndexOf('.');
            if (dot >= 0)
                ext = orig.substring(dot + 1).toLowerCase();

            // for certain types offer browser option
            boolean canOpenInBrowser = ext.equals("pdf") || ext.equals("html") || ext.equals("htm");
            if (canOpenInBrowser) {
                Alert a = new Alert(Alert.AlertType.CONFIRMATION);
                a.setTitle("Open file");
                a.setHeaderText("How would you like to open this file?");
                ButtonType defaultApp = new ButtonType("Default application");
                ButtonType browser = new ButtonType("Open in browser");
                ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
                a.getButtonTypes().setAll(defaultApp, browser, cancel);
                java.util.Optional<ButtonType> res = a.showAndWait();
                if (res.isPresent() && res.get() == browser) {
                    Desktop.getDesktop().browse(tmp.toURI());
                    statusLabel.setText("Opened in browser: " + orig);
                } else if (res.isPresent() && res.get() == defaultApp) {
                    Desktop.getDesktop().open(tmp);
                    statusLabel.setText("Opened with default app: " + orig);
                } else {
                    statusLabel.setText("Open cancelled.");
                }
            } else {
                if (Desktop.isDesktopSupported())
                    Desktop.getDesktop().open(tmp);
                statusLabel.setText("Opened temporary file: " + orig);
            }
        } catch (Exception e) {
            statusLabel.setText("Error: " + e.getMessage());
        }
    }

    @FXML
    public void onExport(ActionEvent ev) {
        String sel = listView.getSelectionModel().getSelectedItem();
        if (sel == null) {
            infoLabel.setText("Select a file first.");
            return;
        }
        String stored = displayToStored.get(sel);
        if (stored == null) {
            infoLabel.setText("Internal mapping missing.");
            return;
        }
        try {
            FileChooser fc = new FileChooser();
            // suggest original filename
            String orig = stored;
            int idx = stored.indexOf("__");
            if (idx >= 0)
                orig = stored.substring(idx + 2).replaceAll("\\.jmn$", "");
            fc.setInitialFileName(orig);
            File dest = fc.showSaveDialog(exportBtn.getScene().getWindow());
            if (dest != null) {
                fileManager.decryptTo(dest, stored, masterKey);
                infoLabel.setText("Exported to: " + dest.getAbsolutePath());
            }
        } catch (Exception e) {
            infoLabel.setText("Export failed: " + e.getMessage());
        }
    }

    @FXML
    public void onRecover(ActionEvent ev) {
        try {
            FileChooser fc = new FileChooser();
            // allow both JuMan backup extension and all files, so renamed backups can still
            // be selected
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("JuMan backup", "*.jumanbackup"));
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("All files", "*.*"));
            File f = fc.showOpenDialog(recoverBtn.getScene().getWindow());
            if (f == null) {
                statusLabel.setText("No backup selected.");
                return;
            }
            // restore into data dir (parent of storage)
            Path dataDir = fileManager.getStorageDir().getParent();
            try {
                backupService.restoreEncryptedBackup(f, masterKey, dataDir);
                statusLabel.setText("Backup restored into: " + dataDir.toAbsolutePath().toString());
            } catch (Exception ex) {
                statusLabel.setText("Restore failed (possible wrong file or key): " + ex.getMessage());
                return;
            }
            refreshList();
        } catch (Exception e) {
            statusLabel.setText("Restore failed: " + e.getMessage());
        }
    }

    @FXML
    public void onBackup(ActionEvent ev) {
        try {
            File enc = backupService.createEncryptedBackup(masterKey);
            infoLabel.setText("Backup created: " + enc.getName());
        } catch (Exception e) {
            infoLabel.setText("Backup failed: " + e.getMessage());
        }
    }

    @FXML
    public void onRefresh(ActionEvent ev) {
        refreshList();
    }

    @FXML
    public void onDelete(ActionEvent ev) {
        String sel = listView.getSelectionModel().getSelectedItem();
        if (sel == null) {
            statusLabel.setText("Select file first.");
            return;
        }
        try {
            String stored = displayToStored.get(sel);
            if (stored == null) {
                statusLabel.setText("Internal mapping missing.");
                return;
            }
            boolean ok = fileManager.deleteStored(stored);
            if (ok)
                statusLabel.setText("Deleted: " + sel);
            else
                statusLabel.setText("File not found or could not be deleted: " + sel);
            refreshList();
        } catch (Exception e) {
            statusLabel.setText("Delete failed: " + e.getMessage());
        }
    }

    private void refreshList() {
        try {
            List<String> items = fileManager.listStored();
            displayToStored.clear();
            List<String> display = new java.util.ArrayList<>();
            for (String s : items) {
                String orig = s;
                int idx = s.indexOf("__");
                if (idx >= 0)
                    orig = s.substring(idx + 2).replaceAll("\\.jmn$", "");
                String disp = orig + "   [" + s + "]";
                displayToStored.put(disp, s);
                display.add(disp);
            }
            listView.getItems().setAll(display);
        } catch (Exception e) {
            infoLabel.setText("Refresh error: " + e.getMessage());
        }
    }
}
