/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package overlayfs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/log"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/epoch"
	"github.com/containerd/continuity/fs"
)

type overlayfsDiff struct {
	store content.Store
}

var emptyDesc = ocispec.Descriptor{}

// NewOverlayfsDiff is a generic implementation of diff.Comparer.  The diff is
// calculated by mounting both the upper and lower mount sets and walking the
// mounted directories concurrently. Changes are calculated by comparing files
// against each other or by comparing file existence between directories.
// NewOverlayfsDiff uses no special characteristics of the mount sets and is
// expected to work with any filesystem.
func NewOverlayfsDiff(store content.Store) diff.Comparer {
	return &overlayfsDiff{
		store: store,
	}
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (s *overlayfsDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (d ocispec.Descriptor, err error) {
	layer, err := overlayMountsToLayer(upper)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get overlay layer: %w", err)
	}
	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}
	if tm := epoch.FromContext(ctx); tm != nil && config.SourceDateEpoch == nil {
		config.SourceDateEpoch = tm
	}

	// if config.MediaType is not set, we default to gzip compressed layer
	if config.MediaType == "" {
		config.MediaType = ocispec.MediaTypeImageLayerGzip
	}

	var compressionType compression.Compression
	switch config.MediaType {
	case ocispec.MediaTypeImageLayer:
		compressionType = compression.Uncompressed
	case ocispec.MediaTypeImageLayerGzip:
		compressionType = compression.Gzip
	case ocispec.MediaTypeImageLayerZstd:
		compressionType = compression.Zstd
	default:
		return emptyDesc, fmt.Errorf("unsupported diff media type: %v: %w", config.MediaType, errdefs.ErrNotImplemented)
	}

	for i, mount := range lower {
		log.L.Debugf("no. %v lower mount source: %v", i, mount.Source)
		log.L.Debugf("no. %v lower mount target: %v", i, mount.Target)
		log.L.Debugf("no. %v lower mount options: %v", i, mount.Options)
		log.L.Debugf("no. %v lower mount type: %v", i, mount.Type)
	}
	for i, mount := range upper {
		log.L.Debugf("no. %v upper mount source: %v", i, mount.Source)
		log.L.Debugf("no. %v upper mount target: %v", i, mount.Target)
		log.L.Debugf("no. %v upper mount options: %v", i, mount.Options)
		log.L.Debugf("no. %v upper mount type: %v", i, mount.Type)
	}

	var ocidesc ocispec.Descriptor
	var newReference bool
	if config.Reference == "" {
		newReference = true
		config.Reference = uniqueRef()
	}

	cw, err := s.store.Writer(ctx,
		content.WithRef(config.Reference),
		content.WithDescriptor(ocispec.Descriptor{
			MediaType: config.MediaType, // most contentstore implementations just ignore this
		}))
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to open writer: %w", err)
	}

	// errOpen is set when an error occurs while the content writer has not been
	// committed or closed yet to force a cleanup
	var errOpen error
	defer func() {
		if errOpen != nil {
			cw.Close()
			if newReference {
				if abortErr := s.store.Abort(ctx, config.Reference); abortErr != nil {
					log.G(ctx).WithError(abortErr).WithField("ref", config.Reference).Warnf("failed to delete diff upload")
				}
			}
		}
	}()
	if !newReference {
		if errOpen = cw.Truncate(0); errOpen != nil {
			return emptyDesc, errOpen
		}
	}

	upperRoot := filepath.Join(layer, "fs")

	if compressionType != compression.Uncompressed {
		dgstr := digest.SHA256.Digester()
		var compressed io.WriteCloser
		if config.Compressor != nil {
			compressed, errOpen = config.Compressor(cw, config.MediaType)
			if errOpen != nil {
				return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", errOpen)
			}
		} else {
			compressed, errOpen = compression.CompressStream(cw, compressionType)
			if errOpen != nil {
				return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", errOpen)
			}
		}
		errOpen = writeDiff(ctx, io.MultiWriter(compressed, dgstr.Hash()), lower, upperRoot, config.SourceDateEpoch)
		compressed.Close()
		if errOpen != nil {
			return emptyDesc, fmt.Errorf("failed to write compressed diff: %w", errOpen)
		}

		if config.Labels == nil {
			config.Labels = map[string]string{}
		}
		config.Labels[labels.LabelUncompressed] = dgstr.Digest().String()
	} else {
		err := writeDiff(ctx, cw, lower, upperRoot, config.SourceDateEpoch)
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to write diff: %w", err)
		}
	}

	var commitopts []content.Opt
	if config.Labels != nil {
		commitopts = append(commitopts, content.WithLabels(config.Labels))
	}

	dgst := cw.Digest()
	if errOpen = cw.Commit(ctx, 0, dgst, commitopts...); errOpen != nil {
		if !errdefs.IsAlreadyExists(errOpen) {
			return emptyDesc, fmt.Errorf("failed to commit: %w", errOpen)
		}
		errOpen = nil
	}

	info, err := s.store.Info(ctx, dgst)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get info from content store: %w", err)
	}
	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}
	// Set "containerd.io/uncompressed" label if digest already existed without label
	if _, ok := info.Labels[labels.LabelUncompressed]; !ok {
		info.Labels[labels.LabelUncompressed] = config.Labels[labels.LabelUncompressed]
		if _, err := s.store.Update(ctx, info, "labels."+labels.LabelUncompressed); err != nil {
			return emptyDesc, fmt.Errorf("error setting uncompressed label: %w", err)
		}
	}

	ocidesc = ocispec.Descriptor{
		MediaType: config.MediaType,
		Size:      info.Size,
		Digest:    info.Digest,
	}

	return ocidesc, nil
}

func uniqueRef() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.UnixNano(), base64.URLEncoding.EncodeToString(b[:]))
}

func writeDiff(ctx context.Context, w io.Writer, lower []mount.Mount, upperRoot string, sourceDateEpoch *time.Time) error {
	var opts []archive.ChangeWriterOpt
	if sourceDateEpoch != nil {
		opts = append(opts, archive.WithModTimeUpperBound(*sourceDateEpoch))
	}

	return mount.WithTempMount(ctx, lower, func(lowerRoot string) error {
		cw := archive.NewChangeWriter(w, upperRoot, opts...)
		if err := fs.DiffDirChanges(ctx, lowerRoot, upperRoot, fs.DiffSourceOverlayFS, cw.HandleChange); err != nil {
			return fmt.Errorf("failed to calculate diff changes: %w", err)
		}
		return cw.Close()
	})
}

// This function extracts the overlay layer from the mount options.
// It expects the first mount to be of type "overlay" and extracts the upper
// directory from the options. If the lower directory is specified, it uses
// the top-level lower directory as the layer. If no lower directory is specified,
// it returns an error indicating that the overlay layer is unsupported for
// This code snippet is credited to the erofs differ:
// https://github.com/erofs/containerd/blob/main/internal/erofsutils/mount_linux.go#L66
func overlayMountsToLayer(mounts []mount.Mount) (string, error) {
	if len(mounts) == 0 {
		return "", errors.New("no mounts provided")
	}
	if mounts[0].Type != "overlay" {
		return "", fmt.Errorf("expected overlay mount type, got %s", mounts[0].Type)
	}
	mnt := mounts[0]
	var layer string
	var topLower string
	for _, o := range mnt.Options {
		if k, v, ok := strings.Cut(o, "="); ok {
			switch k {
			case "upperdir":
				layer = filepath.Dir(v)
			case "lowerdir":
				dir, _, _ := strings.Cut(v, ":")
				topLower = filepath.Dir(dir)
			}
		}
	}
	if layer == "" {
		if topLower == "" {
			return "", fmt.Errorf("unsupported overlay layer for erofs differ: %w", errdefs.ErrNotImplemented)
		}
		layer = topLower
	}
	return layer, nil
}
