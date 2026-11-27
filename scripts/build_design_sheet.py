"""Render the reviewed four-page source; fail if pagination exceeds the limit."""
from pathlib import Path
import html
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from pypdf import PdfReader
BASE=Path(__file__).resolve().parents[1]
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name="Compact",fontSize=8.3,leading=10.5,spaceAfter=5))
styles.add(ParagraphStyle(name="Cell",fontSize=7.5,leading=9))
source=BASE/"docs/DESIGN_SHEET.md"
output=BASE/"docs/DESIGN_SHEET.pdf"
story=[]
def para(text,style="Compact"):
 return Paragraph(html.escape(text),styles[style])
for index,page in enumerate(source.read_text("utf-8").split("---PAGE---")):
 if index:story.append(PageBreak())
 lines=page.strip().splitlines();i=0
 while i<len(lines):
  line=lines[i].strip()
  if line.startswith("|"):
   rows=[]
   while i<len(lines) and lines[i].strip().startswith("|"):
    row=[v.strip() for v in lines[i].strip().strip("|").split("|")]
    if not all(set(v)<=set("-:") for v in row):rows.append([para(v,"Cell") for v in row])
    i+=1
   table=Table(rows,colWidths=[140,165,206],repeatRows=1,hAlign="LEFT")
   table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e4edf4")),("GRID",(0,0),(-1,-1),.35,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
   story.extend([table,Spacer(1,7)]);continue
  if line:story.append(para(line[2:] if line.startswith("# ") else line,"Heading1" if line.startswith("# ") else "Compact"))
  i+=1
SimpleDocTemplate(str(output),pagesize=A4,rightMargin=42,leftMargin=42,topMargin=35,bottomMargin=35,title="ICS505 Combined Treasury Design Sheet",author="John, Essam, Divan, Yassin").build(story)
pages=len(PdfReader(output).pages)
if pages!=4:raise SystemExit(f"Design sheet has {pages} pages, expected exactly 4; shorten source.")
print(f"{output}: {pages} pages")
