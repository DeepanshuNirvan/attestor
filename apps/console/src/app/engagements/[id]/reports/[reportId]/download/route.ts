import { NextResponse } from 'next/server';
import { fetchRaw } from '@/lib/api';

/**
 * Streams a generated report's PDF to staff.
 *
 * The portal has its own download route under `/reports`, a path the console refuses at the edge so
 * a client route can never be served from the staff surface. Until this existed the console could
 * generate a report and had no way to open it. The API records every download, as it does for
 * clients.
 */
export async function GET(
  unusedRequest: Request,
  { params }: { params: Promise<{ id: string; reportId: string }> },
): Promise<NextResponse> {
  const { reportId } = await params;
  const response = await fetchRaw(`/reports/${reportId}/download`);

  if (!response.ok) {
    return NextResponse.json(
      { error: 'that report could not be downloaded' },
      { status: response.status },
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
