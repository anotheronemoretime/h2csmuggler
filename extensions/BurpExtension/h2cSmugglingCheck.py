# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IScanIssue
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.awt.event import ActionListener
import threading


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("h2cSmuggler")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, contextMenuInvocation):
        menuItems = ArrayList()
        menuItem = JMenuItem("Scan for h2c Smuggling")
        menuItem.addActionListener(H2cSmugglingActionListener(self, contextMenuInvocation))
        menuItems.add(menuItem)
        return menuItems


class H2cSmugglingActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation

    def actionPerformed(self, event):
        # Lancer le scan dans un thread séparé
        threading.Thread(target=self.run_scan).start()

    def run_scan(self):
        selectedMessages = self._invocation.getSelectedMessages()
        self._extender._callbacks.printOutput("Selected messages: " + str(len(selectedMessages)))
        if not selectedMessages:
            self._extender._callbacks.printOutput("No messages selected")
            return

        for baseRequestResponse in selectedMessages:
            try:
                self._extender._callbacks.printOutput("Processing request to: " + str(baseRequestResponse.getUrl()))
                request = baseRequestResponse.getRequest()
                requestInfo = self._extender._helpers.analyzeRequest(baseRequestResponse)
                body = request[requestInfo.getBodyOffset():]

                headers = requestInfo.getHeaders()
                newHeaders = []
                for header in headers:
                    if header.startswith("Connection") or header.startswith("Upgrade"):
                        pass
                    else:
                        newHeaders.append(header)
                newHeaders.append("Upgrade: h2c")
                newHeaders.append("HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA")

                connStr = "Connection: Upgrade, HTTP2-Settings"
                h2cRequestOne = self._extender._helpers.buildHttpMessage(newHeaders + [connStr], body)
                connStr = "Connection: Upgrade"
                h2cRequestTwo = self._extender._helpers.buildHttpMessage(newHeaders + [connStr], body)

                self._extender._callbacks.printOutput("Sending first h2c request...")
                requestResponseOne = self._extender._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    h2cRequestOne)
                self._extender._callbacks.printOutput("Sending second h2c request...")
                requestResponseTwo = self._extender._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    h2cRequestTwo)

                self._extender._callbacks.addToSiteMap(requestResponseOne)
                self._extender._callbacks.addToSiteMap(requestResponseTwo)

                responseOneInfo = self._extender._helpers.analyzeResponse(requestResponseOne.getResponse())
                responseTwoInfo = self._extender._helpers.analyzeResponse(requestResponseTwo.getResponse())

                self._extender._callbacks.printOutput("Response 1 status: " + str(responseOneInfo.getStatusCode()))
                self._extender._callbacks.printOutput("Response 2 status: " + str(responseTwoInfo.getStatusCode()))

                if responseOneInfo.getStatusCode() == 101 or responseTwoInfo.getStatusCode() == 101:
                    confidence = "Certain"
                    if baseRequestResponse.getHttpService().getProtocol() != "https":
                        confidence = "Tentative"

                    issue = CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        requestInfo.getUrl(),
                        [requestResponseOne, requestResponseTwo],
                        "HTTP/2 Cleartext (h2c) Upgrade Support Detected",
                        """Server responded with 101 Switching Protocols. If this
                        upgrade response is from a backend server behind a proxy, then
                        intermediary proxy access controls (e.g., path and/or header
                        restrictions) can be bypassed by using
                        h2cSmuggler (https://github.com/BishopFox/h2csmuggler).""",
                        confidence)
                    
                    self._extender._callbacks.addScanIssue(issue)
                    self._extender._callbacks.printOutput("Vulnerability detected and issue created!")
            except Exception as e:
                self._extender._callbacks.printError("Error processing request: " + str(e))


class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
