# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from java.awt import BorderLayout, Dimension, Color
from javax.swing import (JPanel, JButton, JLabel, JTextField, JFileChooser,
                         JTable, JScrollPane, JComboBox, JSplitPane, JTextArea,
                         JPopupMenu, JMenuItem)
from javax.swing.table import DefaultTableModel, TableRowSorter, DefaultTableCellRenderer
from java.net import URL
from threading import Thread
import javax.swing.RowFilter as RowFilter
from java.awt.event import MouseAdapter, MouseEvent

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DirFuzzer")

        self.wordlist_path = None
        self._stop_fuzzing = False
        self.fuzzedItems = []
        self.colorized = False

        self.init_ui()
        callbacks.addSuiteTab(self)

    def init_ui(self):
        from javax.swing import BoxLayout
        from javax.swing import Box

        self.panel = JPanel(BorderLayout())

        top_panel_1 = JPanel()

        self.url_field = JTextField("http://example.com/", 20)
        self.method_selector = JComboBox(["GET", "POST", "HEAD"])
        self.header_field = JTextField("", 15)
        wordlist_button = JButton("Select Wordlist", actionPerformed=self.load_wordlist)
        self.fuzz_button = JButton("Start Fuzzing", actionPerformed=self.start_fuzzing)
        self.wordlist_label = JLabel("Wordlist: No wordlist selected")

        top_panel_1.add(self.url_field)
        top_panel_1.add(self.method_selector)
        top_panel_1.add(JLabel("Custom Header:"))
        top_panel_1.add(self.header_field)
        top_panel_1.add(wordlist_button)
        top_panel_1.add(self.fuzz_button)
        top_panel_1.add(self.wordlist_label)

        top_panel_2 = JPanel()

        self.status_filter = JComboBox(["All", "200", "301", "302", "403", "404", "500"])
        self.status_filter.addActionListener(self.apply_filter)
        self.length_filter_field = JTextField("Exclude Lengths (e.g. 1234,5678)", 10)
        self.exclude_status_field = JTextField("Exclude Status (e.g. 404,403)", 10)
        filter_button = JButton("Apply Filter", actionPerformed=self.apply_filter)
        self.color_button = JButton("Colorize", actionPerformed=self.toggle_colorize)
        export_button = JButton("Export CSV", actionPerformed=self.export_to_csv)
        clear_button = JButton("Clear Table", actionPerformed=self.clear_table)

        top_panel_2.add(self.status_filter)
        top_panel_2.add(self.length_filter_field)
        top_panel_2.add(self.exclude_status_field)
        top_panel_2.add(filter_button)
        top_panel_2.add(self.color_button)
        top_panel_2.add(export_button)
        top_panel_2.add(clear_button)

        self.table_model = DefaultTableModel(["Path", "Status", "Length"], 0)
        self.table = JTable(self.table_model)
        self.table.setPreferredScrollableViewportSize(Dimension(800, 400))
        self.table.setFillsViewportHeight(True)

        self.table_sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.table_sorter)
        self.table.getSelectionModel().addListSelectionListener(self.show_request_response)

        scroll_pane = JScrollPane(self.table)

        req_panel = JPanel(BorderLayout())
        req_panel.add(JLabel("HTTP Request"), BorderLayout.NORTH)
        self.req_area = JTextArea()
        self.req_area.setEditable(False)
        req_panel.add(JScrollPane(self.req_area), BorderLayout.CENTER)

        resp_panel = JPanel(BorderLayout())
        resp_panel.add(JLabel("HTTP Response"), BorderLayout.NORTH)
        self.resp_area = JTextArea()
        self.resp_area.setEditable(False)
        resp_panel.add(JScrollPane(self.resp_area), BorderLayout.CENTER)

        viewer_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_panel, resp_panel)
        viewer_panel.setDividerLocation(400)
        viewer_panel.setPreferredSize(Dimension(800, 200))

        main_panel = JPanel(BorderLayout())
        main_panel.add(scroll_pane, BorderLayout.CENTER)
        main_panel.add(viewer_panel, BorderLayout.SOUTH)

        all_top = JPanel(BorderLayout())
        all_top.add(top_panel_1, BorderLayout.NORTH)
        all_top.add(top_panel_2, BorderLayout.SOUTH)

        self.panel.add(all_top, BorderLayout.NORTH)
        self.panel.add(main_panel, BorderLayout.CENTER)

        popup_menu = JPopupMenu()
        send_to_repeater_item = JMenuItem("Send to Repeater")
        send_to_intruder_item = JMenuItem("Send to Intruder")
        popup_menu.add(send_to_repeater_item)
        popup_menu.add(send_to_intruder_item)
        self.table.addMouseListener(TableMouseListener(self.table, popup_menu))



        def send_to_repeater(event):
            row = self.table.getSelectedRow()
            if row == -1:
                return
            model_row = self.table.convertRowIndexToModel(row)
            item = self.fuzzedItems[model_row]
            request = item[3]
            http_service = item[5]
            if request and http_service:
                self._callbacks.sendToRepeater(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", request, None)

        def send_to_intruder(event):
            row = self.table.getSelectedRow()
            if row == -1:
                return
            model_row = self.table.convertRowIndexToModel(row)
            item = self.fuzzedItems[model_row]
            request = item[3]
            http_service = item[5]
            if request and http_service:
                self._callbacks.sendToIntruder(http_service.getHost(), http_service.getPort(), http_service.getProtocol() == "https", request, None)

        send_to_repeater_item.addActionListener(send_to_repeater)
        send_to_intruder_item.addActionListener(send_to_intruder)
        self.table.addMouseListener(TableMouseListener(self.table, popup_menu))

    def load_wordlist(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            self.wordlist_path = chooser.getSelectedFile().getAbsolutePath()
            self.wordlist_label.setText("Wordlist: " + self.wordlist_path)

    def start_fuzzing(self, event):
        if not self.wordlist_path:
            self.wordlist_label.setText("Please select a wordlist first.")
            return

        if self.fuzz_button.getText() == "Start Fuzzing":
            self._stop_fuzzing = False
            self.fuzzedItems = []
            self.table_model.setRowCount(0)
            self.fuzz_button.setText("Stop Fuzzing")
            url = self.url_field.getText()
            method = self.method_selector.getSelectedItem()
            self.fuzz_thread = Thread(target=self.fuzz, args=[url, method])
            self.fuzz_thread.start()
        else:
            self._stop_fuzzing = True
            self.fuzz_button.setText("Start Fuzzing")

    def fuzz(self, base_url, method):
        try:
            with open(self.wordlist_path, "r") as f:
                paths = [line.strip() for line in f if line.strip()]
        except:
            self.wordlist_label.setText("Error reading wordlist.")
            self.fuzz_button.setText("Start Fuzzing")
            return

        for path in paths:
            if self._stop_fuzzing:
                break
            try:
                full_url = base_url.rstrip("/") + "/" + path
                url_obj = URL(full_url)
                request = self._helpers.buildHttpRequest(url_obj)

                analyzed = self._helpers.analyzeRequest(request)
                headers = list(analyzed.getHeaders())
                body = request[analyzed.getBodyOffset():]

                if method != "GET":
                    headers[0] = method + " " + headers[0].split(" ")[1] + " HTTP/1.1"

                custom_header = self.header_field.getText().strip()
                if custom_header and ":" in custom_header:
                    headers.append(custom_header)

                request = self._helpers.buildHttpMessage(headers, body)

                http_service = self._helpers.buildHttpService(
                    url_obj.getHost(),
                    url_obj.getPort() if url_obj.getPort() != -1 else (443 if url_obj.getProtocol() == "https" else 80),
                    url_obj.getProtocol()
                )

                response = self._callbacks.makeHttpRequest(http_service, request)
                status_code = self._helpers.analyzeResponse(response.getResponse()).getStatusCode()
                length = len(response.getResponse())

                self.fuzzedItems.append((path, status_code, length, request, response, http_service))
                self.table_model.addRow([path, status_code, length])

            except:
                self.fuzzedItems.append((path, "Error", "0", None, None, None))
                self.table_model.addRow([path, "Error", "0"])

        self.fuzz_button.setText("Start Fuzzing")

    def apply_filter(self, event=None):
        selected_status = self.status_filter.getSelectedItem()
        exclude_statuses = [s.strip() for s in self.exclude_status_field.getText().split(",") if s.strip()]
        exclude_lengths = [l.strip() for l in self.length_filter_field.getText().split(",") if l.strip()]

        filters = []

        if selected_status != "All":
            filters.append(RowFilter.regexFilter("^" + selected_status + "$", 1))
        if exclude_statuses:
            filters.append(RowFilter.notFilter(RowFilter.regexFilter("^(%s)$" % "|".join(exclude_statuses), 1)))
        if exclude_lengths:
            filters.append(RowFilter.notFilter(RowFilter.regexFilter("^(%s)$" % "|".join(exclude_lengths), 2)))

        self.table_sorter.setRowFilter(RowFilter.andFilter(filters) if filters else None)

    def toggle_colorize(self, event=None):
        if not self.colorized:
            self.colorize_rows()
            self.color_button.setText("Uncolorize")
            self.colorized = True
        else:
            self.uncolorize_rows()
            self.color_button.setText("Colorize")
            self.colorized = False

    def colorize_rows(self):
        class ColorRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(inner_self, table, value, isSelected, hasFocus, row, column):
                component = DefaultTableCellRenderer.getTableCellRendererComponent(
                    inner_self, table, value, isSelected, hasFocus, row, column)
                model_row = table.convertRowIndexToModel(row)
                status = str(self.table_model.getValueAt(model_row, 1))
                try:
                    code = int(status)
                    if 200 <= code < 300:
                        component.setBackground(Color(100, 200, 100))
                    elif 300 <= code < 400:
                        component.setBackground(Color(200, 200, 80))
                    elif 400 <= code < 500:
                        component.setBackground(Color(240, 140, 60))
                    elif 500 <= code < 600:
                        component.setBackground(Color(200, 50, 50))
                    else:
                        component.setBackground(Color.white)
                    component.setForeground(Color.black)
                except:
                    component.setBackground(Color.white)
                    component.setForeground(Color.black)
                if isSelected:
                    component.setBackground(Color.darkGray)
                    component.setForeground(Color.white)
                return component

        renderer = ColorRenderer()
        for col in range(self.table.getColumnCount()):
            self.table.getColumnModel().getColumn(col).setCellRenderer(renderer)
        self.table.repaint()

    def uncolorize_rows(self):
        for col in range(self.table.getColumnCount()):
            self.table.getColumnModel().getColumn(col).setCellRenderer(DefaultTableCellRenderer())
        self.table.repaint()

    def clear_table(self, event=None):
        self.table_model.setRowCount(0)
        self.fuzzedItems = []

    def export_to_csv(self, event=None):
        from java.io import FileWriter
        chooser = JFileChooser()
        chooser.setDialogTitle("Save CSV")
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.endswith(".csv"):
                path += ".csv"
            try:
                fw = FileWriter(path)
                fw.write("Path,Status,Length\\n")
                for row in range(self.table_model.getRowCount()):
                    fw.write("{},{},{}\\n".format(
                        self.table_model.getValueAt(row, 0),
                        self.table_model.getValueAt(row, 1),
                        self.table_model.getValueAt(row, 2)
                    ))
                fw.close()
                self.wordlist_label.setText("Exported to: " + path)
            except:
                self.wordlist_label.setText("Export failed.")

    def show_request_response(self, event):
        row = self.table.getSelectedRow()
        if row == -1:
            return
        view_row = self.table.convertRowIndexToModel(row)
        item = self.fuzzedItems[view_row]
        request = item[3]
        response = item[4]
        if request is None or response is None:
            return
        self.req_area.setText(self._helpers.bytesToString(request))
        self.resp_area.setText(self._helpers.bytesToString(response.getResponse()))

    def getTabCaption(self):
        return "DirFuzzer"

    def getUiComponent(self):
        return self.panel

class TableMouseListener(MouseAdapter):
    def __init__(self, table, popup_menu):
        self.table = table
        self.popup_menu = popup_menu

    def mousePressed(self, event):
        if event.isPopupTrigger():
            self.show_popup(event)

    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self.show_popup(event)

    def show_popup(self, event):
        row = self.table.rowAtPoint(event.getPoint())
        if row != -1:
            self.table.setRowSelectionInterval(row, row)
            self.popup_menu.show(event.getComponent(), event.getX(), event.getY())
