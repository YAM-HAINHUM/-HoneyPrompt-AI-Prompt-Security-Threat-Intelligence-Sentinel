import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export default function MarkdownMessage({ content }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      skipHtml
      components={{
        table: ({ children }) => (
          <div className="markdown-table-wrapper">
            <table>{children}</table>
          </div>
        ),
        pre: ({ children }) => <pre className="markdown-code-block">{children}</pre>,
      }}
    >
      {typeof content === 'string' ? content : ''}
    </ReactMarkdown>
  );
}
