# Anything related to XML
---


### PROBLEM 1

```
Was thinking that speedy-backend returns XML and that I am playing around with flutter to parse but have lots of trouble. So I decided to convince my stubborn self to look at the docs. 

This is probably the culprit that helps displays the formatted code without the DOMParser in a browser since there are a lot more information in the returned XML. 
If we can parse properly either using Ghidra's very own parser or customizing one XD, we can also highlight syntax and make that part of settings for the future. 

So below shows link(s) hoping it can help decide how to highlight syntax and even do the renaming shiet.

```
-   DecompileResults -> I guess it is to parse the XML strings to display nicely. I may be wrong.
https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileResults.java#L209

-   XMLPullParser -> more like a helper for XML Parsing
https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/Utility/src/main/java/ghidra/xml/XmlPullParser.java#L27

- HighFunction -- Seems like it gives a lot of information of the functions. I assume this to be the first if not first few of the function tags in the returned XML from `binary/code?xxxxxxxx` API from `bridge`. Contains more useful information on how the parsing is done.
https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/HighFunction.java#L214
---