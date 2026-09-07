"""Render a manually researched reference; never imports or reads PandaX results.

Requires reportlab. Run from any directory. Research date is intentionally fixed;
regeneration does not imply that the cited advisories have been researched again.
"""
import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output/pdf/PandaX_Independent_Expected_Results.pdf"
OUT.parent.mkdir(parents=True, exist_ok=True)
font_dir = Path('/System/Library/Fonts/Supplemental')
if (font_dir / 'Arial.ttf').exists():
    pdfmetrics.registerFont(TTFont('Body', str(font_dir / 'Arial.ttf')))
    pdfmetrics.registerFont(TTFont('BodyBold', str(font_dir / 'Arial Bold.ttf')))
    pdfmetrics.registerFontFamily('Body', normal='Body', bold='BodyBold', italic='Body', boldItalic='BodyBold')
    FONT, BOLD = 'Body', 'BodyBold'
else:
    FONT, BOLD = 'Helvetica', 'Helvetica-Bold'
NAVY = colors.HexColor('#142C42')
TEAL = colors.HexColor('#087F83')
GRAY = colors.HexColor('#526273')
PALE = colors.HexColor('#EEF4F7')
styles = {
    'body': ParagraphStyle('body', fontName=FONT, fontSize=10, leading=14, textColor=NAVY, spaceAfter=8),
    'small': ParagraphStyle('small', fontName=FONT, fontSize=8.5, leading=10.5, textColor=GRAY, spaceAfter=4),
    'cell': ParagraphStyle('cell', fontName=FONT, fontSize=8.5, leading=11.5, textColor=NAVY),
    'headcell': ParagraphStyle('headcell', fontName=BOLD, fontSize=8.5, leading=11.5, textColor=colors.white),
    'h1': ParagraphStyle('h1', fontName=BOLD, fontSize=23, leading=27, textColor=NAVY, spaceAfter=15),
    'h2': ParagraphStyle('h2', fontName=BOLD, fontSize=13, leading=17, textColor=TEAL, spaceBefore=12, spaceAfter=7),
    'kicker': ParagraphStyle('kicker', fontName=BOLD, fontSize=9, leading=12, textColor=TEAL, spaceAfter=10),
}
DATA = json.loads((ROOT / 'docs/expected-results-baseline.json').read_text())
SOURCES = [(s['id'],s['title'],s['url']) for s in DATA['sources']]
URLS = {k:u for k,_,u in SOURCES}
story = []
def p(text, style='body'):
    return Paragraph(text, styles[style])
def add(text, style='body'):
    story.append(p(text, style))
def cite(*ids):
    return ' '.join(f'<a href="{escape(URLS[i])}" color="#087F83">[{i}]</a>' for i in ids)
def title(section, heading, sub=None):
    if story: story.append(PageBreak())
    add(section.upper(), 'kicker'); add(heading, 'h1')
    if sub: add(sub)
def table(headers, rows, widths):
    data=[[p(x,'headcell') for x in headers]]+[[p(str(x),'cell') for x in row] for row in rows]
    t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),NAVY),('VALIGN',(0,0),(-1,-1),'TOP'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),
        ('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),
        ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),
        ('LINEBELOW',(0,-1),(-1,-1),0.5,colors.HexColor('#CCD9E0'))]))
    story.append(t);story.append(Spacer(1,8))
def note(text):
    t=Table([[p(text)]],colWidths=[499]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PALE),('BOX',(0,0),(-1,-1),.5,colors.HexColor('#CCD9E0')),('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),10)]));story.append(t)


def expectation(value):
    return {'find':'<font color="#AE3434"><b>SHOULD FIND</b></font>',
            'fixed':'<font color="#197154"><b>NO ACTIVE FINDING</b></font><br/>Fixed',
            'excluded':'<font color="#526273"><b>NO ACTIVE FINDING</b></font><br/>Excluded variant'}[value]

title('PandaX / Independent answer key','What should PandaX find?','Reference 2.0 | Public-source research: 7 September 2026')
add('Pick the exact input below. Each page tells you which named CVEs should appear, which should not be active, and what still needs human review. Write the observed PandaX result in the last column.')
add('<b>Independence:</b> expected vulnerabilities come from the linked public sources. PandaX findings and built-in pass/fail checks are not used to set the answers. Repository input declarations establish scope only. The later test comparison is a separate report.','small')
table(['Input / release','Should find','Should not flag','Page'],[
    (c['title'],str(sum(x['expected']=='find' for x in c['checks'])),str(sum(x['expected']!='find' for x in c['checks'])),str(i+2))
    for i,c in enumerate(DATA['cases'])],[292,69,82,56])
note('<b>Counts refer only to the named checks in this reference.</b> They are not total CVE counts. Extra findings need separate advisory review; a release with no positive checks here may still contain other vulnerabilities.')
add('How to compare','h2')
add('<b>1.</b> Select the exact release. <b>2.</b> Check the component/version in <b>Artifacts</b>. <b>3.</b> Search each CVE in <b>Vulnerabilities</b> with filters cleared. <b>4.</b> Inspect <b>Evidence / applicability</b> and the fixed/excluded reason. <b>5.</b> Record MATCH, MISSING, FALSE POSITIVE or UNRESOLVED.','small')
add('Missing component or failed scan = unresolved coverage, never a clean pass. A component-version finding is not proof that your application can be exploited.','small')

for i,c in enumerate(DATA['cases']):
    title(f'Input {i+1:02d} / '+c['mode'],c['title'])
    if c.get('selector'):add('Select: <b>'+escape(c['selector'])+'</b>','small')
    elif c.get('path'):add('Input: '+escape(c['path']),'small')
    else:add('Official archive: '+escape(c['url'].rsplit('/',1)[-1]),'small')
    present=sum(x['expected']=='find' for x in c['checks']);neg=len(c['checks'])-present
    add(f'<b>{present} named CVE(s) should be found</b> | <b>{neg} should not be active</b>','h2')
    table(['CVE / vulnerability','Component','Expected PoC result','Your observation'],[
        (escape(x['cve'])+' '+cite(x['source'])+'<br/>'+escape(x['name']),escape(x['component']),expectation(x['expected']),'')
        for x in c['checks']],[194,90,123,92])
    add('First check the inventory','h2')
    add('; '.join('<b>'+escape(x['name'])+'</b> '+escape(x['version']) for x in c['inventory'])+'. '+cite(*c.get('inventory_sources',[])),'small')
    add('What changes the interpretation','h2')
    add(escape(c['triage'])+' '+cite(*dict.fromkeys(x['source'] for x in c['checks'])),'small')
    if c['id'].startswith('smarthub'):add('Native WebP build evidence: '+cite('P6'),'small')
    note(escape(c['expected_change']))
    # Present precise fix boundaries without requiring a second advisory lookup.
    fixes={x['cve']:x['fix'] for x in c['checks'] if x['fix']}
    add('Specific CVE fix boundaries: '+ '; '.join(escape(k)+' = '+escape(v) for k,v in fixes.items())+'. These are historical boundaries, not deployment recommendations.','small')

for index,subset in enumerate([SOURCES[:15],SOURCES[15:]]):
    title('Public sources',f'Source register {index+1} of 2','The expected answers above are deductions from these public advisories and official release artifacts.')
    for key,label,url in subset:
        story.append(KeepTogether([p(f'<b>[{key}] <a href="{escape(url)}" color="#087F83">{escape(label)}</a></b>','small'),p(f'<a href="{escape(url)}" color="#526273">{escape(url)}</a>','small'),Spacer(1,4)]))
    if index==1:
        add('Limits of this answer key','h2')
        add('No exhaustive finding counts, live EPSS scores, KEV totals or regulatory deadlines are prescribed. Synthetic product declarations cannot establish deployed components, build flags or runtime reachability. Public advisories establish conditional component-level expectations.','small')

def footer(canvas,doc):
    w,h=A4;canvas.saveState();canvas.setStrokeColor(TEAL);canvas.setLineWidth(1.4);canvas.line(48,h-31,w-48,h-31)
    canvas.setFillColor(GRAY);canvas.setFont(FONT,8);canvas.drawString(48,29,'PandaX | Independent answer key v2.0 | 07 Sep 2026')
    canvas.drawRightString(w-48,29,str(doc.page));canvas.restoreState()

doc=SimpleDocTemplate(str(OUT),pagesize=A4,rightMargin=48,leftMargin=48,topMargin=48,bottomMargin=48,title='PandaX - Independent Expected Results',author='PandaX research reference',subject='Public-source answer key; expected values independent of scanner output')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
print(OUT)
