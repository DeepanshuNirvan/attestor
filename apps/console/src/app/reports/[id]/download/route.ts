import { NextResponse } from 'next/server';
import { fetchRaw } from '@/lib/api';

/**
 * Streams the watermarked PDF.
 *
 * The API's session cookie is SameSite=strict, so a link straight to the API origin would arrive
 * without a session. This forwards the request from the server, and the watermark is applied by the
 * API against the identity in that session — this route cannot influence whose name goes on it.
 */
export async function GET(
  unusedRequest: Request,
  { params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
  const { id } = await params;
  const response = await fetchRaw(`/reports/${id}/download`);

  if (!response.ok) {
    return NextResponse.json(
      { error: 'that document is not available to you' },
      { status: response.status === 401 ? 401 : response.status },
    );
  }

  return new NextResponse(response.body, {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition':
        response.headers.get('content-disposition') ?? `attachment; filename="report.pdf"`,
      'Cache-Control': 'no-store',
    },
  });
}
