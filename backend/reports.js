// Generates downloadable reports (xlsx / docx / pdf) from a chat answer + its data.
// Row-capped so a huge result set can never OOM the box.

const XLSX = require('xlsx');
const PDFDocument = require('pdfkit');
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel,
  Table, TableRow, TableCell, WidthType
} = require('docx');

const MAX_ROWS = 5000;

function aestNow() {
  const d = new Date(Date.now() + 10 * 3600 * 1000);
  return d.toISOString().replace('T', ' ').substring(0, 19) + ' (AEST)';
}

function stripMarkdown(text) {
  return (text || '')
    .replace(/^#{1,6}\s*/gm, '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g, '$1')
    .replace(/`(.+?)`/g, '$1')
    .trim();
}

function prep(data) {
  const rows = Array.isArray(data.rows) ? data.rows : [];
  const capped = rows.slice(0, MAX_ROWS);
  const cols = capped.length ? Object.keys(capped[0]) : [];
  return {
    title: data.title || 'DNS Analysis Report',
    question: data.question || '',
    answer: stripMarkdown(data.answer || ''),
    sql: data.sql || '',
    rows: capped,
    cols: cols,
    total: rows.length,
    truncated: rows.length > MAX_ROWS,
    generated: aestNow()
  };
}

function buildXlsx(data) {
  const d = prep(data);
  const wb = XLSX.utils.book_new();
  const summary = [
    ['DNS Analysis Report'],
    [],
    ['Generated', d.generated],
    ['Question', d.question],
    ['Rows returned', d.total],
    d.truncated ? ['Note', 'Showing first ' + MAX_ROWS + ' of ' + d.total + ' rows'] : ['', ''],
    [],
    ['Analysis']
  ].concat(d.answer.split('\n').map(function (l) { return [l]; }))
   .concat([[], ['SQL used'], [d.sql]]);
  const ws1 = XLSX.utils.aoa_to_sheet(summary);
  ws1['!cols'] = [{ wch: 18 }, { wch: 100 }];
  XLSX.utils.book_append_sheet(wb, ws1, 'Report');
  if (d.rows.length) {
    const ws2 = XLSX.utils.json_to_sheet(d.rows);
    ws2['!cols'] = d.cols.map(function () { return { wch: 22 }; });
    XLSX.utils.book_append_sheet(wb, ws2, 'Data');
  }
  return XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
}

async function buildDocx(data) {
  const d = prep(data);
  const kids = [];
  kids.push(new Paragraph({ text: d.title, heading: HeadingLevel.HEADING_1 }));
  kids.push(new Paragraph({ children: [new TextRun({ text: 'Generated: ' + d.generated, italics: true, size: 18 })] }));
  kids.push(new Paragraph({ children: [new TextRun({ text: 'Question: ' + d.question, italics: true, size: 18 })] }));
  kids.push(new Paragraph({ children: [new TextRun({ text: 'Rows returned: ' + d.total + (d.truncated ? ' (showing first ' + MAX_ROWS + ')' : ''), italics: true, size: 18 })] }));
  kids.push(new Paragraph({ text: '' }));
  kids.push(new Paragraph({ text: 'Analysis', heading: HeadingLevel.HEADING_2 }));
  d.answer.split('\n').forEach(function (line) {
    kids.push(new Paragraph({ children: [new TextRun({ text: line, size: 22 })] }));
  });
  if (d.rows.length) {
    kids.push(new Paragraph({ text: '' }));
    kids.push(new Paragraph({ text: 'Data', heading: HeadingLevel.HEADING_2 }));
    const header = new TableRow({
      children: d.cols.map(function (c) {
        return new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: String(c), bold: true, size: 18 })] })] });
      })
    });
    const limit = Math.min(d.rows.length, 500);
    const body = d.rows.slice(0, limit).map(function (r) {
      return new TableRow({
        children: d.cols.map(function (c) {
          return new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: r[c] === null || r[c] === undefined ? '' : String(r[c]), size: 18 })] })] });
        })
      });
    });
    kids.push(new Table({ rows: [header].concat(body), width: { size: 100, type: WidthType.PERCENTAGE } }));
    if (d.rows.length > limit) {
      kids.push(new Paragraph({ children: [new TextRun({ text: 'Table truncated to ' + limit + ' rows; full data in the xlsx export.', italics: true, size: 16 })] }));
    }
  }
  if (d.sql) {
    kids.push(new Paragraph({ text: '' }));
    kids.push(new Paragraph({ text: 'Query used', heading: HeadingLevel.HEADING_2 }));
    kids.push(new Paragraph({ children: [new TextRun({ text: d.sql, font: 'Courier New', size: 16 })] }));
  }
  const doc = new Document({ sections: [{ children: kids }] });
  return await Packer.toBuffer(doc);
}

function buildPdf(data) {
  const d = prep(data);
  return new Promise(function (resolve, reject) {
    try {
      const doc = new PDFDocument({ margin: 45, size: 'A4' });
      const chunks = [];
      doc.on('data', function (c) { chunks.push(c); });
      doc.on('end', function () { resolve(Buffer.concat(chunks)); });
      doc.on('error', reject);
      doc.fontSize(18).text(d.title);
      doc.moveDown(0.3);
      doc.fontSize(9).fillColor('#555')
        .text('Generated: ' + d.generated)
        .text('Question: ' + d.question)
        .text('Rows returned: ' + d.total + (d.truncated ? ' (showing first ' + MAX_ROWS + ')' : ''));
      doc.moveDown(0.8);
      doc.fillColor('#000').fontSize(13).text('Analysis');
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor('#111').text(d.answer, { align: 'left' });
      if (d.rows.length) {
        doc.moveDown(0.8);
        doc.fontSize(13).fillColor('#000').text('Data');
        doc.moveDown(0.3);
        doc.fontSize(8).fillColor('#111');
        const limit = Math.min(d.rows.length, 300);
        doc.text(d.cols.join('  |  '));
        doc.moveDown(0.2);
        for (let i = 0; i < limit; i++) {
          const r = d.rows[i];
          doc.text(d.cols.map(function (c) {
            return r[c] === null || r[c] === undefined ? '' : String(r[c]);
          }).join('  |  '));
        }
        if (d.rows.length > limit) {
          doc.moveDown(0.3);
          doc.fillColor('#555').text('Truncated to ' + limit + ' rows; full data in the xlsx export.');
        }
      }
      if (d.sql) {
        doc.moveDown(0.8);
        doc.fontSize(13).fillColor('#000').text('Query used');
        doc.moveDown(0.3);
        doc.font('Courier').fontSize(8).fillColor('#333').text(d.sql);
      }
      doc.end();
    } catch (e) { reject(e); }
  });
}

async function build(format, data) {
  const f = (format || 'xlsx').toLowerCase();
  if (f === 'xlsx') return { buf: buildXlsx(data), ext: 'xlsx', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' };
  if (f === 'docx') return { buf: await buildDocx(data), ext: 'docx', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' };
  if (f === 'pdf') return { buf: await buildPdf(data), ext: 'pdf', mime: 'application/pdf' };
  throw new Error('Unknown format: ' + format);
}

module.exports = { build: build, MAX_ROWS: MAX_ROWS };
