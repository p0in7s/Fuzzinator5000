import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.RawEditor;

public class Fuzzinator5000 implements BurpExtension {
    private MontoyaApi api;
    
    // Editors
    private HttpRequestEditor request1Editor;
    private HttpRequestEditor request2Editor;
    private HttpResponseEditor response1Viewer;
    private HttpResponseEditor response2Viewer;
    private RawEditor comparatorEditor;
    
    // Fuzzing components
    private JTable fuzzTable;
    private DefaultTableModel tableModel;
    private JTextArea payloadArea;
    private JTextField positionMarkerField;
    private JButton startFuzzBtn;
    private JButton stopFuzzBtn;
    private JButton loadWordlistBtn;
    private JButton testRequest1Btn;
    private JButton clearResultsBtn;
    private JButton viewResponseBtn;
    private JTextField filterSizeField;
    private JCheckBox autoRunRequest2Checkbox;
    private JCheckBox sequentialModeCheckbox;
    private JLabel payloadCountLabel;
    private JLabel fuzzStatusLabel;
    
    // UI Components
    private JPanel mainPanel;
    private JSplitPane verticalSplit;
    private JButton runBothBtn;
    private JButton runRequest1Btn;
    private JButton runRequest2Btn;
    private JToggleButton compareToggle;
    private JToggleButton syncToggle;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    
    // State
    private HttpRequestResponse lastResponse1;
    private HttpRequestResponse lastResponse2;
    private boolean isFuzzing = false;
    private ExecutorService executorService;
    private AtomicInteger completedCounter = new AtomicInteger(0);
    private int totalPayloads = 0;
    
    // Store fuzzing results for viewing
    private List<Fuzzinator5000Result> fuzzingResults = new ArrayList<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Fuzzinator5000");
        
        initializeEditors();
        initializeUI();
        registerContextMenu();
        registerSuiteTab();
    }
    
    private void initializeEditors() {
        request1Editor = api.userInterface().createHttpRequestEditor();
        request2Editor = api.userInterface().createHttpRequestEditor();
        response1Viewer = api.userInterface().createHttpResponseEditor();
        response2Viewer = api.userInterface().createHttpResponseEditor();
        comparatorEditor = api.userInterface().createRawEditor();
        comparatorEditor.setEditable(false);
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(0, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create toolbar
        JPanel toolbar = createToolbar();
        
        // Create request/response pairs
        JPanel requestResponsePair1 = createRequestResponsePair("Request 1", request1Editor, "Response 1", response1Viewer);
        JPanel requestResponsePair2 = createRequestResponsePair("Request 2", request2Editor, "Response 2", response2Viewer);
        
        // Create vertical split for the two request/response pairs
        verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestResponsePair1, requestResponsePair2);
        verticalSplit.setResizeWeight(0.5);
        verticalSplit.setDividerSize(8);
        verticalSplit.setOneTouchExpandable(true);
        
        // Create fuzzing panel
        JPanel fuzzerPanel = createFuzzerPanel();
        
        // Create comparator panel
        JPanel comparatorPanel = createComparatorPanel();
        
        // Create status bar
        JPanel statusBar = createStatusBar();
        
        // Create main split pane (request/response pairs on top, fuzzer on bottom)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, verticalSplit, fuzzerPanel);
        mainSplit.setResizeWeight(0.65); // Give 65% space to request/response pairs
        mainSplit.setDividerSize(8);
        mainSplit.setOneTouchExpandable(true);
        
        // Layout
        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(mainSplit, BorderLayout.CENTER);
        mainPanel.add(comparatorPanel, BorderLayout.EAST);
        mainPanel.add(statusBar, BorderLayout.PAGE_END);
    }
    
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        toolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        
        // Action buttons
        runBothBtn = createStyledButton("▶ Run Both Requests", Color.decode("#4CAF50"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { runBothRequests(); }
        });
        
        runRequest1Btn = createStyledButton("▶ Run Request 1", Color.decode("#2196F3"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { runSingleRequest(1); }
        });
        
        runRequest2Btn = createStyledButton("▶ Run Request 2", Color.decode("#2196F3"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { runSingleRequest(2); }
        });
        
        // Test Request 1 button
        testRequest1Btn = createStyledButton("🔧 Test Request 1 with Fuzzing", Color.decode("#FF9800"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { testRequest1(); }
        });
        
        // Toggle buttons
        compareToggle = new JToggleButton("🔍 Compare Responses");
        compareToggle.setToolTipText("Show response comparison in Comparator panel");
        compareToggle.addActionListener(e -> updateComparatorVisibility());
        
        syncToggle = new JToggleButton("🔗 Auto-Scroll");
        syncToggle.setToolTipText("Auto-scroll response viewers to bottom");
        syncToggle.setSelected(true);
        
        // Add components to toolbar
        toolbar.add(runBothBtn);
        toolbar.add(runRequest1Btn);
        toolbar.add(runRequest2Btn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(testRequest1Btn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(compareToggle);
        toolbar.add(syncToggle);
        
        return toolbar;
    }

    private JPanel createRequestResponsePair(String requestTitle, HttpRequestEditor requestEditor, String responseTitle, HttpResponseEditor responseEditor) {
        JPanel pairPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        
        // Request panel
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder(requestTitle));
        requestPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        
        // Response panel
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder(responseTitle));
        responsePanel.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        
        pairPanel.add(requestPanel);
        pairPanel.add(responsePanel);
        
        return pairPanel;
    }
    
    private JPanel createFuzzerPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("⚡ Fuzzinator5000 Engine"));
        
        // Controls panel
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        
        positionMarkerField = new JTextField("FUZZ", 8);
        positionMarkerField.setToolTipText("Marker to replace in Request 1 (default: FUZZ)");
        
        autoRunRequest2Checkbox = new JCheckBox("Auto-run Request 2", true);
        autoRunRequest2Checkbox.setToolTipText("Automatically run Request 2 after each Request 1 iteration");
        
        sequentialModeCheckbox = new JCheckBox("Sequential (Request 1 → Request 2, no overlap)", true);
        sequentialModeCheckbox.setToolTipText("On: one payload at a time. Off: multithreaded iterations.");
        
        loadWordlistBtn = createStyledButton("📁 Load Wordlist", Color.decode("#9C27B0"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { loadWordlist(); }
        });
        
        startFuzzBtn = createStyledButton("▶ Start Fuzzing", Color.decode("#4CAF50"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { startFuzzing(); }
        });
        
        stopFuzzBtn = createStyledButton("⏹ Stop Fuzzing", Color.decode("#F44336"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { stopFuzzing(); }
        });
        stopFuzzBtn.setEnabled(false);
        
        clearResultsBtn = createStyledButton("🗑️ Clear Results", Color.decode("#795548"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { clearResults(); }
        });
        
        viewResponseBtn = createStyledButton("👁️ View Response", Color.decode("#009688"), new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) { viewSelectedResponse(); }
        });
        
        filterSizeField = new JTextField("", 8);
        filterSizeField.setToolTipText("Filter by Response 2 size (press Enter)");
        filterSizeField.addActionListener(e -> filterTableBySize());
        
        payloadCountLabel = new JLabel("Payloads: 0");
        
        fuzzStatusLabel = new JLabel("Ready");
        fuzzStatusLabel.setForeground(Color.BLUE);
        
        controlsPanel.add(new JLabel("Marker:"));
        controlsPanel.add(positionMarkerField);
        controlsPanel.add(autoRunRequest2Checkbox);
        controlsPanel.add(sequentialModeCheckbox);
        controlsPanel.add(loadWordlistBtn);
        controlsPanel.add(startFuzzBtn);
        controlsPanel.add(stopFuzzBtn);
        controlsPanel.add(clearResultsBtn);
        controlsPanel.add(viewResponseBtn);
        controlsPanel.add(new JLabel("Filter Response 2 Size:"));
        controlsPanel.add(filterSizeField);
        controlsPanel.add(payloadCountLabel);
        controlsPanel.add(Box.createHorizontalStrut(10));
        controlsPanel.add(fuzzStatusLabel);
        
        // Payload area
        payloadArea = new JTextArea(2, 20);
        payloadArea.setText("admin\nuser\ntest\npassword\nadmin123");
        payloadArea.setLineWrap(false);
        payloadArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updatePayloadCount(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updatePayloadCount(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updatePayloadCount(); }
        });
        updatePayloadCount();
        
        JScrollPane payloadScrollPane = new JScrollPane(payloadArea);
        payloadScrollPane.setBorder(BorderFactory.createTitledBorder("Payloads (one per line)"));
        
        // Table for results
        String[] columnNames = {
            "Iteration #", "Payload", 
            "Request 1 Status", "Request 1 Size", 
            "Request 2 Status", "Request 2 Size",
            "Request 2 Time", "Notes"
        };
        
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 3 || columnIndex == 5) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        
        fuzzTable = new JTable(tableModel);
        fuzzTable.setAutoCreateRowSorter(true);
        
        // Center align numeric and status columns
        javax.swing.table.DefaultTableCellRenderer centerRenderer = new javax.swing.table.DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(javax.swing.JLabel.CENTER);
        
        // Left align for Payload (col 1) and Notes (col 7)
        javax.swing.table.DefaultTableCellRenderer leftRenderer = new javax.swing.table.DefaultTableCellRenderer();
        leftRenderer.setHorizontalAlignment(javax.swing.JLabel.LEFT);
        
        for (int i = 0; i < tableModel.getColumnCount(); i++) {
            if (i == 1 || i == 7) {  // Payload and Notes columns
                fuzzTable.getColumnModel().getColumn(i).setCellRenderer(leftRenderer);
            } else {
                fuzzTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
            }
        }
        
        // Double-click to load result
        fuzzTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                if (evt.getClickCount() == 2) {
                    viewSelectedResponse();
                }
            }
        });
        
        JScrollPane tableScrollPane = new JScrollPane(fuzzTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("Fuzzing Results"));
        
        // Layout for payload and table
        JSplitPane fuzzerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, payloadScrollPane, tableScrollPane);
        fuzzerSplit.setResizeWeight(0.25); // 25% for payloads, 75% for results
        fuzzerSplit.setDividerSize(5);
        
        panel.add(controlsPanel, BorderLayout.NORTH);
        panel.add(fuzzerSplit, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createComparatorPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Comparator"));
        panel.setVisible(false);
        panel.setPreferredSize(new Dimension(300, 0));
        
        panel.add(new JScrollPane(comparatorEditor.uiComponent()), BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout(10, 0));
        statusBar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        
        statusLabel = new JLabel("Ready - Waiting for user action");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN));
        
        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        
        statusBar.add(statusLabel, BorderLayout.WEST);
        statusBar.add(progressBar, BorderLayout.CENTER);
        
        return statusBar;
    }
    
    private JButton createStyledButton(String text, Color bgColor, AbstractAction action) {
        JButton button = new JButton(action);
        button.setText(text);
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        // Hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(bgColor.darker());
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(bgColor);
            }
        });
        
        return button;
    }
    
    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> menuItems = new ArrayList<>();
                
                event.selectedRequestResponses().forEach(rr -> {
                    JMenu fuzzinator5000Menu = new JMenu("Send to Fuzzinator5000");
                    
                    JMenuItem toRequest1 = new JMenuItem("Request 1");
                    toRequest1.addActionListener(e -> {
                        request1Editor.setRequest(rr.request());
                        if (rr.response() != null) {
                            response1Viewer.setResponse(rr.response());
                            lastResponse1 = rr;
                        }
                        setStatus("Request 1 loaded from context menu", false);
                    });
                    
                    JMenuItem toRequest2 = new JMenuItem("Request 2");
                    toRequest2.addActionListener(e -> {
                        request2Editor.setRequest(rr.request());
                        if (rr.response() != null) {
                            response2Viewer.setResponse(rr.response());
                            lastResponse2 = rr;
                        }
                        setStatus("Request 2 loaded from context menu", false);
                    });
                    
                    JMenuItem swap = new JMenuItem("Swap Requests");
                    swap.addActionListener(e -> swapRequests());
                    
                    JMenuItem sendToFuzzer = new JMenuItem("Use as Fuzzer Base");
                    sendToFuzzer.addActionListener(e -> {
                        request1Editor.setRequest(rr.request());
                        setStatus("Request loaded as fuzzer base - add FUZZ marker", false);
                    });
                    
                    fuzzinator5000Menu.add(toRequest1);
                    fuzzinator5000Menu.add(toRequest2);
                    fuzzinator5000Menu.add(new JSeparator());
                    fuzzinator5000Menu.add(swap);
                    fuzzinator5000Menu.add(sendToFuzzer);
                    
                    menuItems.add(fuzzinator5000Menu);
                });
                
                return menuItems;
            }
        });
    }
    
    private void registerSuiteTab() {
        api.userInterface().registerSuiteTab("Fuzzinator5000", mainPanel);
    }
    
    // ================================
    // REQUEST EXECUTION METHODS
    // ================================
    
    private void runBothRequests() {
        if (isFuzzing) {
            setStatus("⚠️ Cannot run while fuzzing is active - use Stop Fuzzing button first", false);
            return;
        }
        
        setStatus("Running both requests...", true);
        
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                // Run Request 1
                lastResponse1 = executeRequest(request1Editor.getRequest(), response1Viewer, 1);
                
                // Run Request 2
                lastResponse2 = executeRequest(request2Editor.getRequest(), response2Viewer, 2);
                
                return null;
            }
            
            @Override
            protected void done() {
                setStatus("Both requests completed", false);
                
                if (compareToggle.isSelected() && lastResponse1 != null && lastResponse2 != null) {
                    updateComparator();
                }
                
                if (syncToggle.isSelected()) {
                    syncResponseScrolling();
                }
            }
        };
        
        worker.execute();
    }
    
    private void runSingleRequest(int requestNumber) {
        if (isFuzzing) {
            setStatus("⚠️ Cannot run while fuzzing is active - use Stop Fuzzing button first", false);
            return;
        }
        
        String requestName = requestNumber == 1 ? "Request 1" : "Request 2";
        setStatus("▶ Running " + requestName + "...", true);
        
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                if (requestNumber == 1) {
                    lastResponse1 = executeRequest(request1Editor.getRequest(), response1Viewer, 1);
                } else {
                    lastResponse2 = executeRequest(request2Editor.getRequest(), response2Viewer, 2);
                }
                return null;
            }
            
            @Override
            protected void done() {
                setStatus("✓ " + requestName + " completed successfully", false);
                
                if (syncToggle.isSelected()) {
                    syncResponseScrolling();
                }
            }
        };
        
        worker.execute();
    }
    
    private HttpRequestResponse executeRequest(HttpRequest request, HttpResponseEditor editor, int reqNum) {
        if (request == null) {
            SwingUtilities.invokeLater(() ->
                setStatus("Error: Request " + reqNum + " is null", false));
            return null;
        }

        try {
            HttpRequest toSend = request;
            // Auto-fix Content-Length for Request 1
            if (reqNum == 1) {
                String adjusted = adjustContentLength(request.toString());
                toSend = HttpRequest.httpRequest(request.httpService(), adjusted);
            }

            HttpRequestResponse response = api.http().sendRequest(toSend);

            SwingUtilities.invokeLater(() -> {
                if (response != null && response.response() != null) {
                    editor.setResponse(response.response());
                }
            });

            return response;

        } catch (Exception e) {
            SwingUtilities.invokeLater(() ->
                setStatus("Error executing Request " + reqNum + ": " +
                         (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()), false));
            return null;
        }
    }
    
    // ================================
    // FUZZING METHODS
    // ================================
    
    private void updatePayloadCount() {
        String text = payloadArea.getText().trim();
        if (text.isEmpty()) {
            payloadCountLabel.setText("Payloads: 0");
            return;
        }
        
        String[] lines = text.split("\n");
        int count = 0;
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                count++;
            }
        }
        payloadCountLabel.setText("Payloads: " + count);
    }
    
    private void loadWordlist() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Wordlist File");
        
        int result = fileChooser.showOpenDialog(mainPanel);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                List<String> lines = new ArrayList<>();
                try (BufferedReader reader = new BufferedReader(new FileReader(fileChooser.getSelectedFile()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        lines.add(line);
                    }
                }
                
                StringBuilder sb = new StringBuilder();
                for (String line : lines) {
                    if (!line.trim().isEmpty()) {
                        sb.append(line).append("\n");
                    }
                }
                
                payloadArea.setText(sb.toString());
                setStatus("Loaded " + lines.size() + " lines from wordlist", false);
            } catch (Exception e) {
                setStatus("Failed to load wordlist: " + e.getMessage(), false);
                JOptionPane.showMessageDialog(mainPanel, 
                    "Error loading wordlist:\n" + e.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void testRequest1() {
        HttpRequest baseRequest = request1Editor.getRequest();
        if (baseRequest == null) {
            setStatus("❌ Error: No Request 1 loaded for testing", false);
            return;
        }

        final String markerTemp = positionMarkerField.getText().trim();

        String baseRequestStr = baseRequest.toString();
        if (!baseRequestStr.contains(markerTemp)) {
            JOptionPane.showMessageDialog(mainPanel,
                "Marker '" + markerTemp + "' not found in Request 1.",
                "Marker Not Found",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        String testPayloadTemp = "TEST123";
        for (String line : payloadArea.getText().split("\n")) {
            if (!line.trim().isEmpty()) {
                testPayloadTemp = line.trim();
                break;
            }
        }

        final String fuzzedRequestStr = baseRequestStr.replace(markerTemp, testPayloadTemp);
        final HttpRequest baseReq = baseRequest;
        final String testPayload = testPayloadTemp;

        SwingWorker<HttpRequestResponse, Void> worker = new SwingWorker<>() {
            @Override
            protected HttpRequestResponse doInBackground() {
                try {
                    String adjustedRequest = adjustContentLength(fuzzedRequestStr);
                    HttpRequest testRequest = HttpRequest.httpRequest(baseReq.httpService(), adjustedRequest);
                    return api.http().sendRequest(testRequest);
                } catch (Exception e) {
                    api.logging().logToOutput("[TEST REQUEST 1] Error: " + e.getMessage());
                    return HttpRequestResponse.httpRequestResponse(
                        baseReq,
                        HttpResponse.httpResponse(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nTest Error: " + e.getMessage()
                        )
                    );
                }
            }

            @Override
            protected void done() {
                try {
                    HttpRequestResponse response = get();
                    if (response != null && response.response() != null) {
                        response1Viewer.setResponse(response.response());
                        setStatus("✓ Test Request 1 completed - Status: " + response.response().statusCode(), false);
                    }
                    if (response != null && response.response() != null) {
                        response1Viewer.setResponse(response.response());
                        JOptionPane.showMessageDialog(mainPanel,
                            "✓ Test Request 1 completed successfully\n\n" +
                            "Marker: " + markerTemp + "\n" +
                            "Test Payload: " + testPayload + "\n" +
                            "Response shown in Response 1 viewer",
                            "Test Request 1 Result",
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(mainPanel,
                            "❌ Test Request 1 failed: No response received",
                            "Test Request 1 Result",
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    setStatus("❌ Test Request 1 failed: " + e.getMessage(), false);
                    api.logging().logToOutput("[TEST REQUEST 1] Exception: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void startFuzzing() {
        if (isFuzzing) return;
        
        HttpRequest baseRequest1 = request1Editor.getRequest();
        if (baseRequest1 == null) {
            setStatus("❌ Error: No Request 1 loaded for fuzzing", false);
            JOptionPane.showMessageDialog(mainPanel,
                "Please load a request into Request 1 first",
                "No Request 1",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // Parse payloads
        String payloadsText = payloadArea.getText().trim();
        if (payloadsText.isEmpty()) {
            setStatus("❌ Error: No payloads specified", false);
            JOptionPane.showMessageDialog(mainPanel,
                "Please add payloads to the payload area",
                "No Payloads",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        String[] lines = payloadsText.split("\n");
        List<String> payloads = new ArrayList<>();
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                payloads.add(trimmed);
            }
        }
        
        if (payloads.isEmpty()) {
            setStatus("❌ Error: No valid payloads found", false);
            return;
        }
        
        // Get marker
        String marker = positionMarkerField.getText().trim();
        if (marker.isEmpty()) {
            marker = "FUZZ";
        }
        
        String baseRequestStr = baseRequest1.toString();
        
        // Check if marker exists
        if (!baseRequestStr.contains(marker)) {
            JOptionPane.showMessageDialog(mainPanel,
                "Marker '" + marker + "' not found in Request 1.\n\n" +
                "Add '" + marker + "' to Request 1 where payloads should be injected.",
                "Marker Not Found",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        // IMPORTANT: Warn if marker might be in Host header or URL
        if (couldBreakHttpRequest(baseRequestStr, marker)) {
            int choice = JOptionPane.showConfirmDialog(mainPanel,
                "⚠️ WARNING: Marker placement may break HTTP request!\n\n" +
                "The marker '" + marker + "' is in a sensitive location\n" +
                "(Host header, URL path, or HTTP method).\n\n" +
                "This could cause fuzzing to fail.\n\n" +
                "Do you want to continue anyway?",
                "Potential Request Breakage",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            
            if (choice != JOptionPane.YES_OPTION) {
                setStatus("⏸️ Fuzzing cancelled by user - marker placement warning", false);
                return;
            }
        }
        
        // Get Request 2
        HttpRequest baseRequest2 = request2Editor.getRequest();
        
        // Clear previous results
        tableModel.setRowCount(0);
        fuzzingResults.clear();
        completedCounter.set(0);
        totalPayloads = payloads.size();
        
        // Start fuzzing
        isFuzzing = true;
        startFuzzBtn.setEnabled(false);
        stopFuzzBtn.setEnabled(true);
        progressBar.setVisible(true);
        progressBar.setMaximum(totalPayloads);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        
        boolean sequential = sequentialModeCheckbox.isSelected();
        int threads = sequential ? 1 : 3;
        executorService = Executors.newFixedThreadPool(threads);
        
        setFuzzStatus("Starting Fuzzinator5000 (" + (sequential ? "sequential" : threads + " threads") + ")...", Color.BLUE);
        setStatus("⚡ Fuzzinator5000 started (" + (sequential ? "sequential" : threads + " threads") + ") with " + totalPayloads + " payloads | Marker: '" + marker + "' | Auto-run Request 2: " + (autoRunRequest2Checkbox.isSelected() ? "Yes" : "No"), true);
        api.logging().logToOutput("[FUZZINATOR5000 START] Payloads: " + totalPayloads + " | Marker: " + marker + " | Threads: " + threads + (sequential ? " (sequential)" : ""));
        
        // Store final variables for thread safety
        final String finalBaseRequestStr = baseRequestStr;
        final String finalMarker = marker;
        final HttpRequest finalBaseRequest1 = baseRequest1;
        final HttpRequest finalBaseRequest2 = baseRequest2;
        
        for (int i = 0; i < payloads.size(); i++) {
            final String payload = payloads.get(i);
            final int iteration = i + 1;
            
            executorService.submit(() -> {
                try {
                    String fuzzedRequest1Str = finalBaseRequestStr.replace(finalMarker, payload);
                    String adjustedRequest1Str = adjustContentLength(fuzzedRequest1Str);
                    HttpRequest fuzzedRequest1 = HttpRequest.httpRequest(
                        finalBaseRequest1.httpService(),
                        adjustedRequest1Str
                    );

                    long start = System.currentTimeMillis();
                    HttpRequestResponse response1;
                    try {
                        response1 = api.http().sendRequest(fuzzedRequest1);
                    } catch (Exception e) {
                        api.logging().logToOutput("[FUZZINATOR5000] Iteration " + iteration + " - Request 1 Error: " + e.getMessage());
                        response1 = HttpRequestResponse.httpRequestResponse(
                            fuzzedRequest1,
                            HttpResponse.httpResponse(
                                "HTTP/1.1 0 Error\r\nContent-Type: text/plain\r\n\r\nRequest 1 Error: " + e.getMessage()
                            )
                        );
                    }
                    long req1Time = System.currentTimeMillis() - start;

                    // Execute Request 2 AFTER Request 1 completes
                    HttpRequestResponse response2 = null;
                    long req2Time = 0;
                    if (finalBaseRequest2 != null && autoRunRequest2Checkbox.isSelected()) {
                        long startTime = System.currentTimeMillis();
                        try {
                            response2 = api.http().sendRequest(finalBaseRequest2);
                        } catch (Exception e) {
                            api.logging().logToOutput("[FUZZINATOR5000] Iteration " + iteration + " - Request 2 Error: " + e.getMessage());
                            response2 = HttpRequestResponse.httpRequestResponse(
                                finalBaseRequest2,
                                HttpResponse.httpResponse(
                                    "HTTP/1.1 0 Error\r\nContent-Type: text/plain\r\n\r\nRequest 2 Error: " + e.getMessage()
                                )
                            );
                        }
                        req2Time = System.currentTimeMillis() - startTime;
                    }

                    final HttpRequestResponse finalResponse1 = response1;
                    final HttpRequestResponse finalResponse2 = response2;
                    final long finalReq2Time = req2Time;
                    
                    Fuzzinator5000Result result = new Fuzzinator5000Result(
                        iteration,
                        payload,
                        fuzzedRequest1,
                        response1,
                        response2,
                        req1Time,
                        finalReq2Time
                    );
                    fuzzingResults.add(result);
                    
                    SwingUtilities.invokeLater(() -> {
                        int completed = completedCounter.incrementAndGet();
                        
                        String req1Status = "Error";
                        int req1Size = 0;
                        if (finalResponse1 != null && finalResponse1.response() != null) {
                            req1Status = String.valueOf(finalResponse1.response().statusCode());
                            req1Size = finalResponse1.response().body().length();
                        } else if (finalResponse1 != null) {
                            req1Status = "No Response";
                        }
                        
                        String req2Status = "N/A";
                        int req2Size = 0;
                        if (finalResponse2 != null && finalResponse2.response() != null) {
                            req2Status = String.valueOf(finalResponse2.response().statusCode());
                            req2Size = finalResponse2.response().body().length();
                        } else if (finalBaseRequest2 != null && autoRunRequest2Checkbox.isSelected()) {
                            req2Status = "Error";
                        }
                        
                        String notes = "Request 1: " + req1Status;
                        if (!"N/A".equals(req2Status)) notes += " | Request 2: " + req2Status;
                        
                        Object[] rowData = {
                            iteration,
                            payload,
                            req1Status,
                            req1Size,
                            req2Status,
                            req2Size,
                            finalReq2Time + "ms",
                            notes
                        };
                        
                        tableModel.addRow(rowData);
                        updateProgress(completed);
                        setFuzzStatus("Running: " + completed + "/" + totalPayloads, Color.BLUE);
                        
                        if (completed >= totalPayloads) {
                            stopFuzzing();
                            setFuzzStatus("Fuzzing Complete", Color.decode("#4CAF50"));
                            setStatus("✓ Fuzzinator5000 completed successfully: " + totalPayloads + " iterations processed", false);
                            api.logging().logToOutput("[FUZZINATOR5000 END] Completed all " + totalPayloads + " iterations");
                        }
                    });
                    
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        int completed = completedCounter.incrementAndGet();
                        api.logging().logToOutput("[FUZZINATOR5000] Iteration " + iteration + " - Exception: " + e.getMessage());
                        Object[] rowData = {
                            iteration,
                            payload,
                            "Exception",
                            0,
                            "N/A",
                            0,
                            "0ms",
                            "ERROR: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName())
                        };
                        tableModel.addRow(rowData);
                        updateProgress(completed);
                        if (completed >= totalPayloads) {
                            stopFuzzing();
                            setFuzzStatus("Fuzzing Complete with Errors", Color.RED);
                            setStatus("⚠️ Fuzzinator5000 completed with errors - check output for details", false);
                            api.logging().logToOutput("[FUZZINATOR5000 END] Completed with " + completed + " errors");
                        }
                    });
                }
            });
        }
    }
    
    private void stopFuzzing() {
        if (!isFuzzing) return;
        
        isFuzzing = false;
        startFuzzBtn.setEnabled(true);
        stopFuzzBtn.setEnabled(false);
        progressBar.setVisible(false);
        
        if (executorService != null) {
            executorService.shutdownNow();
            try {
                if (!executorService.awaitTermination(2, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
            executorService = null;
        }
        
        setStatus("⏹️ Fuzzing stopped by user", false);
        api.logging().logToOutput("[FUZZINATOR5000 STOP] Fuzzing stopped by user");
    }
    
    // ================================
    // RESULTS VIEWING METHODS
    // ================================
    
    private void clearResults() {
        if (isFuzzing) {
            JOptionPane.showMessageDialog(mainPanel,
                "Cannot clear results while fuzzing is active",
                "Fuzzing Active",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int confirm = JOptionPane.showConfirmDialog(mainPanel,
            "Clear all fuzzing results?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            tableModel.setRowCount(0);
            fuzzingResults.clear();
            setStatus("Results cleared", false);
        }
    }
    
    private void viewSelectedResponse() {
        int viewRow = fuzzTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(mainPanel,
                "Please select a row first",
                "No Selection",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        int modelRow = fuzzTable.convertRowIndexToModel(viewRow);
        
        if (modelRow >= fuzzingResults.size()) {
            JOptionPane.showMessageDialog(mainPanel,
                "Response data not available for this row",
                "Data Unavailable",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        Fuzzinator5000Result result = fuzzingResults.get(modelRow);
        
        // Create dialog to view response
        JPanel viewPanel = new JPanel(new BorderLayout());
        
        // Create tabs for different views
        javax.swing.JTabbedPane tabbedPane = new javax.swing.JTabbedPane();
        
        // Tab 1: Response 1
        if (result.response1 != null && result.response1.response() != null) {
            HttpResponseEditor responseViewer1 = api.userInterface().createHttpResponseEditor();
            responseViewer1.setResponse(result.response1.response());
            JPanel panel1 = new JPanel(new BorderLayout());
            panel1.add(responseViewer1.uiComponent(), BorderLayout.CENTER);
            tabbedPane.addTab("Response 1 (" + result.response1.response().statusCode() + ")", panel1);
        }
        
        // Tab 2: Response 2
        if (result.response2 != null && result.response2.response() != null) {
            HttpResponseEditor responseViewer2 = api.userInterface().createHttpResponseEditor();
            responseViewer2.setResponse(result.response2.response());
            JPanel panel2 = new JPanel(new BorderLayout());
            panel2.add(responseViewer2.uiComponent(), BorderLayout.CENTER);
            tabbedPane.addTab("Response 2 (" + result.response2.response().statusCode() + ")", panel2);
        }
        
        // Tab 3: Request 1
        if (result.fuzzedRequest1 != null) {
            HttpRequestEditor requestViewer = api.userInterface().createHttpRequestEditor();
            requestViewer.setRequest(result.fuzzedRequest1);
            JPanel panel3 = new JPanel(new BorderLayout());
            panel3.add(requestViewer.uiComponent(), BorderLayout.CENTER);
            tabbedPane.addTab("Fuzzed Request 1", panel3);
        }
        
        // Tab 4: Summary
        JTextArea summaryArea = new JTextArea();
        summaryArea.setEditable(false);
        summaryArea.setText(getResultSummary(result, modelRow));
        JScrollPane summaryScroll = new JScrollPane(summaryArea);
        tabbedPane.addTab("Summary", summaryScroll);
        
        viewPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton sendToRequest1 = new JButton("Send to Request 1");
        sendToRequest1.addActionListener(e -> {
            if (result.fuzzedRequest1 != null) {
                request1Editor.setRequest(result.fuzzedRequest1);
                setStatus("Request loaded from iteration #" + (modelRow + 1), false);
            }
        });
        
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> {
            Window window = SwingUtilities.getWindowAncestor(viewPanel);
            if (window != null) {
                window.dispose();
            }
        });
        
        buttonPanel.add(sendToRequest1);
        buttonPanel.add(closeBtn);
        viewPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Show dialog
        javax.swing.JDialog dialog = new javax.swing.JDialog(
            SwingUtilities.getWindowAncestor(mainPanel),
            "Fuzzing Result #" + (modelRow + 1),
            javax.swing.JDialog.ModalityType.APPLICATION_MODAL
        );
        
        dialog.setContentPane(viewPanel);
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(mainPanel);
        dialog.setVisible(true);
    }
    
    private String getResultSummary(Fuzzinator5000Result result, int rowIndex) {
        StringBuilder summary = new StringBuilder();
        summary.append("FUZZINATOR5000 RESULT DETAILS\n");
        summary.append("==============================\n\n");
        
        summary.append("Iteration: ").append(rowIndex + 1).append("\n");
        summary.append("Payload: ").append(result.payload).append("\n\n");
        
        summary.append("REQUEST 1:\n");
        summary.append("----------\n");
        if (result.response1 != null && result.response1.response() != null) {
            summary.append("Status: ").append(result.response1.response().statusCode()).append("\n");
            summary.append("Size: ").append(result.response1.response().body().length()).append(" bytes\n");
            summary.append("Time: ").append(result.req1Time).append(" ms\n");
        } else {
            summary.append("No response received\n");
        }
        
        summary.append("\nREQUEST 2:\n");
        summary.append("----------\n");
        if (result.response2 != null && result.response2.response() != null) {
            summary.append("Status: ").append(result.response2.response().statusCode()).append("\n");
            summary.append("Size: ").append(result.response2.response().body().length()).append(" bytes\n");
            summary.append("Time: ").append(result.req2Time).append(" ms\n");
        } else {
            summary.append("Not executed or no response\n");
        }
        
        summary.append("\nDIFFERENCES:\n");
        summary.append("------------\n");
        if (result.response1 != null && result.response1.response() != null && 
            result.response2 != null && result.response2.response() != null) {
            
            int size1 = result.response1.response().body().length();
            int size2 = result.response2.response().body().length();
            int status1 = result.response1.response().statusCode();
            int status2 = result.response2.response().statusCode();
            
            if (status1 != status2) {
                summary.append("✓ Status codes differ: ").append(status1).append(" vs ").append(status2).append("\n");
            }
            if (size1 != size2) {
                summary.append("✓ Response sizes differ: ").append(size1).append(" vs ").append(size2).append(" bytes\n");
            }
            if (status1 == status2 && size1 == size2) {
                summary.append("✓ Responses appear identical\n");
            }
        } else {
            summary.append("Cannot compare - missing responses\n");
        }
        
        return summary.toString();
    }
    
    private void filterTableBySize() {
        String filterText = filterSizeField.getText().trim();
        if (filterText.isEmpty()) {
            // Clear filter
            TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) fuzzTable.getRowSorter();
            if (sorter != null) {
                sorter.setRowFilter(null);
            }
            setStatus("Filter cleared", false);
            return;
        }
        
        try {
            int targetSize = Integer.parseInt(filterText);
            
            TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
            fuzzTable.setRowSorter(sorter);
            
            // Filter by Response 2 size (column index 5)
            sorter.setRowFilter(RowFilter.numberFilter(RowFilter.ComparisonType.EQUAL, targetSize, 5));
            
            int rowCount = fuzzTable.getRowCount();
            setStatus("Filtered to " + rowCount + " rows with Response 2 size = " + targetSize, false);
        } catch (NumberFormatException e) {
            setStatus("Invalid size filter. Enter a number.", false);
        }
    }
    
    // ================================
    // HELPER METHODS
    // ================================

    private String adjustContentLength(String requestStr) {
        if (requestStr == null || requestStr.isEmpty()) return requestStr;

        String[] parts = requestStr.split("\r?\n\r?\n", 2);
        if (parts.length < 2) return requestStr; // no body

        String headers = parts[0];
        String body = parts[1];
        int len = body.getBytes(StandardCharsets.UTF_8).length;

        String[] headerLines = headers.split("\r?\n");
        boolean found = false;
        StringBuilder newHeaders = new StringBuilder();

        for (String line : headerLines) {
            if (line.toLowerCase().startsWith("content-length:")) {
                newHeaders.append("Content-Length: ").append(len).append("\r\n");
                found = true;
            } else {
                newHeaders.append(line).append("\r\n");
            }
        }
        if (!found) {
            newHeaders.append("Content-Length: ").append(len).append("\r\n");
        }

        return newHeaders.append("\r\n").append(body).toString();
    }
    
    private boolean isValidHttpRequest(String requestStr) {
        if (requestStr == null || requestStr.trim().isEmpty()) {
            return false;
        }
        
        String[] lines = requestStr.split("\r?\n");
        if (lines.length < 1) {
            return false;
        }
        
        String firstLine = lines[0].trim();
        if (!firstLine.matches("^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT) .+ HTTP/\\d+(\\.\\d+)?$")) {
            return false;
        }
        
        boolean hasHost = false;
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].toLowerCase().startsWith("host:")) {
                hasHost = true;
                break;
            }
        }
        
        boolean hasAbsoluteUrl = firstLine.contains("http://") || firstLine.contains("https://");
        
        return hasHost || hasAbsoluteUrl;
    }
    
    private boolean couldBreakHttpRequest(String requestStr, String marker) {
        String[] lines = requestStr.split("\r?\n");
        
        if (lines.length > 0 && lines[0].contains(marker)) {
            return true;
        }
        
        for (String line : lines) {
            if (line.toLowerCase().startsWith("host:") && line.contains(marker)) {
                return true;
            }
        }
        
        return false;
    }
    
    private void updateProgress(int completed) {
        progressBar.setValue(completed);
        progressBar.setString(completed + "/" + totalPayloads);
    }
    
    private void setFuzzStatus(String message, Color color) {
        SwingUtilities.invokeLater(() -> {
            fuzzStatusLabel.setText(message);
            fuzzStatusLabel.setForeground(color);
            api.logging().logToOutput("[FUZZINATOR5000] " + message);
        });
    }

    private void setStatus(String message, boolean showProgress) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(message);
            progressBar.setVisible(showProgress);
            
            if (showProgress) {
                statusLabel.setForeground(Color.BLUE);
            } else {
                statusLabel.setForeground(Color.BLACK);
            }
            
            api.logging().logToOutput("[STATUS] " + message);
        });
    }
    
    private String getFirstLines(String text, int maxLines) {
        String[] lines = text.split("\r?\n");
        StringBuilder result = new StringBuilder();
        int linesToShow = Math.min(lines.length, maxLines);
        for (int i = 0; i < linesToShow; i++) {
            result.append(lines[i]);
            if (i < linesToShow - 1) result.append("\n");
        }
        if (lines.length > maxLines) {
            result.append("\n... [truncated]");
        }
        return result.toString();
    }
    
    private void swapRequests() {
        HttpRequest req1 = request1Editor.getRequest();
        HttpRequest req2 = request2Editor.getRequest();
        
        request1Editor.setRequest(req2);
        request2Editor.setRequest(req1);
        
        HttpResponse resp1 = response1Viewer.getResponse();
        HttpResponse resp2 = response2Viewer.getResponse();
        
        if (resp1 != null && resp2 != null) {
            response1Viewer.setResponse(resp2);
            response2Viewer.setResponse(resp1);
        }
        
        HttpRequestResponse temp = lastResponse1;
        lastResponse1 = lastResponse2;
        lastResponse2 = temp;
        
        setStatus("Requests and responses swapped", false);
    }
    
    private void updateComparatorVisibility() {
        Component parent = comparatorEditor.uiComponent().getParent().getParent();
        if (parent != null) {
            parent.setVisible(compareToggle.isSelected());
            if (compareToggle.isSelected() && lastResponse1 != null && lastResponse2 != null) {
                updateComparator();
            }
        }
    }
    
    private void updateComparator() {
        if (lastResponse1 == null || lastResponse2 == null) {
            comparatorEditor.setContents(burp.api.montoya.core.ByteArray.byteArray("Not enough data to compare".getBytes()));
            return;
        }
        
        StringBuilder comparison = new StringBuilder();
        comparison.append("=== RESPONSE COMPARISON ===\n\n");
        
        int status1 = lastResponse1.response().statusCode();
        int status2 = lastResponse2.response().statusCode();
        comparison.append("Status Codes: ").append(status1).append(" vs ").append(status2);
        comparison.append(status1 == status2 ? " ✓\n" : " ✗\n");
        
        int length1 = lastResponse1.response().body().length();
        int length2 = lastResponse2.response().body().length();
        comparison.append("Body Length: ").append(length1).append(" vs ").append(length2);
        comparison.append(length1 == length2 ? " ✓\n" : " ✗\n");
        
        comparison.append("\n=== HEADERS ===\n");
        comparison.append("Response 1 Headers:\n");
        lastResponse1.response().headers().forEach(h -> comparison.append("  ").append(h).append("\n"));
        
        comparison.append("\nResponse 2 Headers:\n");
        lastResponse2.response().headers().forEach(h -> comparison.append("  ").append(h).append("\n"));
        
        comparison.append("\n=== RESPONSE SNIPPETS ===\n");
        comparison.append("Response 1 (first 2000 chars):\n");
        comparison.append(truncate(lastResponse1.response().bodyToString(), 2000)).append("\n\n");
        
        comparison.append("Response 2 (first 2000 chars):\n");
        comparison.append(truncate(lastResponse2.response().bodyToString(), 2000)).append("\n");
        
        comparatorEditor.setContents(burp.api.montoya.core.ByteArray.byteArray(comparison.toString().getBytes()));
    }
    
    private void syncResponseScrolling() {
        SwingUtilities.invokeLater(() -> {
            scrollToBottom(response1Viewer.uiComponent());
            scrollToBottom(response2Viewer.uiComponent());
        });
    }
    
    private void scrollToBottom(Component component) {
        if (component instanceof JScrollPane) {
            JScrollPane scrollPane = (JScrollPane) component;
            JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
            verticalBar.setValue(verticalBar.getMaximum());
        }
    }
    
    private String truncate(String text, int maxLength) {
        if (text == null || text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength) + "\n\n...[truncated]";
    }
    
    // Inner class to store fuzzing results
    private static class Fuzzinator5000Result {
        int iteration;
        String payload;
        HttpRequest fuzzedRequest1;
        HttpRequestResponse response1;
        HttpRequestResponse response2;
        long req1Time;
        long req2Time;
        
        Fuzzinator5000Result(int iteration, String payload, HttpRequest fuzzedRequest1, HttpRequestResponse response1, HttpRequestResponse response2, long req1Time, long req2Time) {
            this.iteration = iteration;
            this.payload = payload;
            this.fuzzedRequest1 = fuzzedRequest1;
            this.response1 = response1;
            this.response2 = response2;
            this.req1Time = req1Time;
            this.req2Time = req2Time;
        }
    }
}